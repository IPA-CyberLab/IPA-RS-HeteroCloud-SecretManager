#!/usr/bin/env python3
"""Initialize and unseal the dedicated three-node OpenBao cluster.

The first initialization response is encrypted to the operator's SSH key before
any share is copied to a host. Each host then seals one share with its systemd
host credential key. The encrypted response is an independent recovery copy.
No plaintext key or token is written to a persistent file or printed.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time


PODS = {
    'openbao-0': ('uc-k8sp2', '163.220.236.52'),
    'openbao-1': ('uc-k8sp1', '163.220.236.51'),
    'openbao-2': ('uc-k8s3p', '163.220.236.53'),
}
CRED = '/etc/heteronetwork/openbao-custody/unseal-share.cred'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(argv, *, data=None, timeout=45, env=None):
    return subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)


def kubectl(kubeconfig, *args, timeout=45):
    result = run(['kubectl', '--kubeconfig', str(kubeconfig), '--request-timeout=20s',
                  *args], timeout=timeout)
    require(result.returncode == 0, 'Kubernetes API request failed')
    return result.stdout


def ssh_sudo(args, address, script, data=b'', *, missing_ok=False):
    command = [
        'ssh', '-i', str(args.ssh_key), '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', f'UserKnownHostsFile={args.known_hosts}',
        f'mizuame@{address}',
        "sudo -S -p '' /bin/sh -c " + shlex.quote(script),
    ]
    password = os.environ['HNN_IAC_BECOME_PASSWORD'].encode() + b'\n'
    result = run(command, data=password + data, timeout=45)
    if missing_ok and result.returncode == 44:
        return None
    require(result.returncode == 0, f'Host credential operation failed on {address}')
    return result.stdout


def host_share(args, address):
    return ssh_sudo(args, address,
                    f'test -f {CRED} || exit 44; systemd-creds decrypt {CRED} -',
                    missing_ok=True)


def stage_share(args, address, share):
    current = host_share(args, address)
    if current is not None:
        require(current == share, f'Existing share differs on {address}')
        return
    script = (
        'set -eu; umask 077; '
        'install -d -m 0700 /etc/heteronetwork/openbao-custody; '
        f'test ! -e {CRED}; '
        f'systemd-creds encrypt --with-key=host --name=unseal-share - {CRED} >/dev/null; '
        f'chmod 0600 {CRED}'
    )
    ssh_sudo(args, address, script, share)
    require(host_share(args, address) == share,
            f'Host-bound share verification failed on {address}')


def operator_public_key(args):
    result = run(['ssh-keygen', '-y', '-f', str(args.ssh_key)])
    require(result.returncode == 0 and result.stdout.startswith(b'ssh-ed25519 '),
            'The operator SSH key cannot be used as an age recipient')
    public = args.recovery_dir / 'operator-ssh.pub'
    if public.exists():
        require(public.read_bytes() == result.stdout, 'Operator recovery key changed')
    else:
        public.write_bytes(result.stdout)
        public.chmod(0o600)
    return public


def preflight_age(args, public):
    probe = args.recovery_dir / '.age-preflight.tmp'
    require(not probe.exists(), 'An incomplete age preflight artifact needs review')
    try:
        encrypted = run(['age', '-R', str(public), '-o', str(probe)], data=b'openbao-custody-probe')
        require(encrypted.returncode == 0, 'Operator recovery encryption is unavailable')
        decrypted = run(['age', '-d', '-i', str(args.ssh_key), str(probe)])
        require(decrypted.returncode == 0 and decrypted.stdout == b'openbao-custody-probe',
                'Operator recovery decryption is unavailable')
    finally:
        probe.unlink(missing_ok=True)


def save_encrypted_init(args, public, response):
    target = args.recovery_dir / 'openbao-init.json.age'
    require(not target.exists(), 'Initialization recovery artifact already exists')
    temporary = args.recovery_dir / '.openbao-init.json.age.tmp'
    require(not temporary.exists(), 'An incomplete initialization artifact needs review')
    result = run(['age', '-R', str(public), '-o', str(temporary)], data=response)
    require(result.returncode == 0 and temporary.is_file(),
            'Could not encrypt the initialization response')
    temporary.chmod(0o600)
    with temporary.open('rb') as encrypted:
        os.fsync(encrypted.fileno())
    os.replace(temporary, target)
    directory = os.open(args.recovery_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return target


def load_encrypted_init(args):
    target = args.recovery_dir / 'openbao-init.json.age'
    require(target.is_file() and not target.is_symlink(),
            'Encrypted initialization recovery artifact is missing')
    result = run(['age', '-d', '-i', str(args.ssh_key), str(target)])
    require(result.returncode == 0, 'Cannot decrypt the initialization recovery artifact')
    return result.stdout


def init_response(raw):
    response = json.loads(raw)
    shares = response.get('keys_base64')
    require(isinstance(shares, list) and len(shares) == 3 and
            all(isinstance(share, str) and len(share) >= 32 for share in shares),
            'Initialization response has no complete three-share set')
    require(isinstance(response.get('root_token'), str) and response['root_token'],
            'Initialization response has no root token')
    return [share.encode('ascii') + b'\n' for share in shares]


class BaoAPI:
    def __init__(self, args, ca):
        self.args = args
        self.ca = ca
        self.processes = []

    def __enter__(self):
        try:
            for index, pod in enumerate(PODS):
                port = self.args.base_port + index
                proc = subprocess.Popen([
                    'kubectl', '--kubeconfig', str(self.args.kubeconfig),
                    '-n', 'openbao', 'port-forward', f'pod/{pod}', f'{port}:8200',
                    '--address', '127.0.0.1',
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.processes.append(proc)
            for index, proc in enumerate(self.processes):
                port = self.args.base_port + index
                for _ in range(40):
                    require(proc.poll() is None, 'OpenBao port-forward failed')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                            break
                    except OSError:
                        time.sleep(0.25)
                else:
                    raise RuntimeError('OpenBao port-forward timed out')
        except Exception:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_):
        for proc in self.processes:
            proc.terminate()
        for proc in self.processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def request(self, pod, path, data=None):
        index = list(PODS).index(pod)
        port = self.args.base_port + index
        name = f'{pod}.openbao-internal.openbao.svc.cluster.local'
        command = [
            'curl', '--silent', '--show-error', '--fail-with-body',
            '--max-time', '15', '--noproxy', '*', '--cacert', str(self.ca),
            '--resolve', f'{name}:{port}:127.0.0.1',
            '-H', 'Content-Type: application/json',
        ]
        if data is not None:
            command += ['--request', 'PUT', '--data-binary', '@-']
        command.append(f'https://{name}:{port}/v1/{path}')
        result = run(command, data=data, timeout=25)
        require(result.returncode == 0, f'OpenBao API request failed for {pod}/{path}')
        return json.loads(result.stdout)


def wait_initialized(api, pod):
    for _ in range(60):
        status = api.request(pod, 'sys/seal-status')
        if status.get('initialized'):
            return status
        time.sleep(2)
    raise RuntimeError(f'{pod} did not join the initialized Raft cluster')


def unseal(api, pod, shares):
    status = wait_initialized(api, pod)
    if not status['sealed']:
        return
    for share in shares[:2]:
        status = api.request(pod, 'sys/unseal',
                             json.dumps({'key': share.decode('ascii').strip()}).encode())
        if not status['sealed']:
            return
    require(False, f'{pod} did not unseal with the two host-held shares')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--ssh-key', type=Path, required=True)
    parser.add_argument('--known-hosts', type=Path, required=True)
    parser.add_argument('--recovery-dir', type=Path, required=True)
    parser.add_argument('--base-port', type=int, default=18400)
    args = parser.parse_args()
    os.umask(0o077)
    require(os.environ.get('HNN_IAC_BECOME_PASSWORD'), 'Sudo password must be supplied in the process environment')
    require(args.ssh_key.is_file() and not args.ssh_key.is_symlink()
            and args.known_hosts.is_file() and not args.known_hosts.is_symlink(),
            'Operator SSH inputs are missing or linked')
    require(stat.S_IMODE(args.ssh_key.stat().st_mode) & 0o077 == 0,
            'Operator SSH key permissions are too broad')
    require(1024 < args.base_port < 65533, 'Invalid local port range')
    args.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    recovery_stat = args.recovery_dir.lstat()
    require(stat.S_ISDIR(recovery_stat.st_mode) and recovery_stat.st_uid == os.geteuid()
            and stat.S_IMODE(recovery_stat.st_mode) & 0o077 == 0,
            'Recovery directory is accessible to another user')
    public = operator_public_key(args)
    preflight_age(args, public)
    cert = kubectl(args.kubeconfig, '-n', 'openbao', 'get', 'secret',
                   'openbao-server-tls', '-o', 'jsonpath={.data.ca\\.crt}')
    require(cert, 'OpenBao TLS CA is missing')
    with tempfile.TemporaryDirectory(prefix='openbao-bootstrap-', dir='/dev/shm') as temporary:
        ca = Path(temporary) / 'ca.crt'
        ca.write_bytes(base64.b64decode(cert))
        with BaoAPI(args, ca) as api:
            backup = args.recovery_dir / 'openbao-init.json.age'
            initialized = api.request('openbao-0', 'sys/init')['initialized']
            if backup.exists():
                require(initialized, 'Recovery artifact exists but OpenBao is not initialized')
                raw = load_encrypted_init(args)
            else:
                require(not initialized, 'OpenBao is initialized but no recovery artifact exists')
                for _, address in PODS.values():
                    require(host_share(args, address) is None,
                            f'An unexpected host share already exists on {address}')
                raw = json.dumps(api.request('openbao-0', 'sys/init',
                                             b'{"secret_shares":3,"secret_threshold":2}'),
                                 separators=(',', ':')).encode()
                init_response(raw)
                save_encrypted_init(args, public, raw)
            shares = init_response(raw)
            for (_, address), share in zip(PODS.values(), shares):
                stage_share(args, address, share)
            held = [host_share(args, address) for _, address in PODS.values()]
            require(held == shares, 'One or more host-held shares differ from the recovery copy')
            for pod in PODS:
                unseal(api, pod, held)
    print(json.dumps({'initialized': True, 'unsealed': sorted(PODS),
                      'host_custodians': sorted(host for host, _ in PODS.values()),
                      'recovery_artifact': str(args.recovery_dir / 'openbao-init.json.age')}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            json.JSONDecodeError, subprocess.TimeoutExpired):
        print('OpenBao bootstrap failed; protected values were not printed.', file=sys.stderr)
        sys.exit(1)
