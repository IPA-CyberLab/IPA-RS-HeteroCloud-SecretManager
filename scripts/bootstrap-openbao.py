#!/usr/bin/env python3
"""Initialize and unseal the dedicated three-node OpenBao cluster.

The first initialization response is encrypted to a dedicated age key before
any share is copied to a host. Each host then seals one share with its systemd
host credential key. Retire the all-share artifact after the initial root token
is revoked; later unseal operations read host-held shares and use two of them.
No plaintext key or token is written to a persistent file or printed.
"""

import argparse
import base64
import getpass
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
    password = args.sudo_password.encode() + b'\n'
    result = run(command, data=password + data, timeout=45)
    if missing_ok and result.returncode == 44:
        return None
    require(result.returncode == 0, f'Host credential operation failed on {address}')
    return result.stdout


def host_share(args, address):
    return ssh_sudo(args, address,
                    f'test -f {CRED} || exit 44; '
                    f'systemd-creds decrypt --name=unseal-share {CRED} -',
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
    if args.recovery_identity:
        result = run(['age-keygen', '-y', str(args.recovery_identity)])
        public = args.recovery_dir / 'recovery-age.pub'
        require(result.returncode == 0 and result.stdout.startswith(b'age1'),
                'The dedicated age recovery identity is unavailable')
    else:
        result = run(['ssh-keygen', '-y', '-f', str(args.ssh_key)])
        public = args.recovery_dir / 'operator-ssh.pub'
        require(result.returncode == 0 and result.stdout.startswith(b'ssh-ed25519 '),
                'The operator SSH key cannot be used as an age recipient')
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
        decrypted = run(['age', '-d', '-i', str(args.recovery_identity or args.ssh_key),
                         str(probe)])
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
    result = run(['age', '-d', '-i', str(args.recovery_identity or args.ssh_key),
                  str(target)])
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
        self.available = []

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
                for _ in range(40):
                    if proc.poll() is not None:
                        break
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                            self.available.append(pod)
                            break
                    except OSError:
                        time.sleep(0.25)
                if pod not in self.available:
                    proc.terminate()
                    proc.wait(timeout=5)
            require(len(self.available) >= 2,
                    'At least two OpenBao Pods must be reachable for Raft quorum')
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
        require(pod in self.available, f'{pod} is unavailable')
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
    for _ in range(30):
        if not api.request(pod, 'sys/seal-status')['sealed']:
            return
        time.sleep(1)
    require(False, f'{pod} did not unseal with the two host-held shares')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--ssh-key', type=Path, required=True)
    parser.add_argument('--recovery-identity', type=Path,
                        help='Dedicated age identity for the encrypted init artifact')
    parser.add_argument('--known-hosts', type=Path, required=True)
    parser.add_argument('--recovery-dir', type=Path, required=True)
    parser.add_argument('--host-custody-only', action='store_true',
                        help='Use only shares held on the three custodian hosts')
    parser.add_argument('--base-port', type=int, default=18400)
    args = parser.parse_args()
    os.umask(0o077)
    args.sudo_password = os.environ.pop('HNN_IAC_BECOME_PASSWORD', None)
    if not args.sudo_password:
        args.sudo_password = getpass.getpass('Custodian hosts sudo password: ')
    require(args.sudo_password and '\n' not in args.sudo_password,
            'A valid custodian sudo password is required')
    require(args.ssh_key.is_file() and not args.ssh_key.is_symlink()
            and args.known_hosts.is_file() and not args.known_hosts.is_symlink(),
            'Operator SSH inputs are missing or linked')
    require(stat.S_IMODE(args.ssh_key.stat().st_mode) & 0o077 == 0,
            'Operator SSH key permissions are too broad')
    if args.recovery_identity:
        require(args.recovery_identity.is_file() and not args.recovery_identity.is_symlink()
                and stat.S_IMODE(args.recovery_identity.stat().st_mode) & 0o077 == 0,
                'Recovery age identity is missing or accessible to others')
    require(1024 < args.base_port < 65533, 'Invalid local port range')
    args.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    recovery_stat = args.recovery_dir.lstat()
    require(stat.S_ISDIR(recovery_stat.st_mode) and recovery_stat.st_uid == os.geteuid()
            and stat.S_IMODE(recovery_stat.st_mode) & 0o077 == 0,
            'Recovery directory is accessible to another user')
    cert = kubectl(args.kubeconfig, '-n', 'openbao', 'get', 'secret',
                   'openbao-server-tls', '-o', 'jsonpath={.data.ca\\.crt}')
    require(cert, 'OpenBao TLS CA is missing')
    with tempfile.TemporaryDirectory(prefix='openbao-bootstrap-', dir='/dev/shm') as temporary:
        ca = Path(temporary) / 'ca.crt'
        ca.write_bytes(base64.b64decode(cert))
        with BaoAPI(args, ca) as api:
            backup = args.recovery_dir / 'openbao-init.json.age'
            used_backup = backup.exists() and not args.host_custody_only
            initialized = api.request(api.available[0], 'sys/init')['initialized']
            if used_backup:
                require(initialized, 'Recovery artifact exists but OpenBao is not initialized')
                require(len(api.available) == len(PODS),
                        'All three OpenBao Pods are required while staging initial shares')
                public = operator_public_key(args)
                preflight_age(args, public)
                raw = load_encrypted_init(args)
                shares = init_response(raw)
                for (_, address), share in zip(PODS.values(), shares):
                    stage_share(args, address, share)
            elif not initialized:
                require(len(api.available) == len(PODS),
                        'All three OpenBao Pods are required for initialization')
                public = operator_public_key(args)
                preflight_age(args, public)
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
            held = []
            for _, address in PODS.values():
                try:
                    held.append(host_share(args, address))
                except RuntimeError:
                    if used_backup or not initialized:
                        raise
                    held.append(None)
            available_shares = [share for share in held if share]
            require(len(available_shares) >= 2 and
                    len(set(available_shares)) == len(available_shares),
                    'At least two distinct host-held unseal shares are required')
            if used_backup or not initialized:
                require(len(available_shares) == 3,
                        'Three host-held shares are required during initialization')
            for share in available_shares:
                require(len(base64.b64decode(share.strip(), validate=True)) >= 16,
                        'A host-held unseal share is malformed')
            if used_backup:
                require(held == shares,
                        'One or more host-held shares differ from the recovery copy')
            for pod in api.available:
                unseal(api, pod, available_shares)
            unsealed_pods = sorted(api.available)
    print(json.dumps({'initialized': True, 'unsealed': unsealed_pods,
                      'host_custodians': sorted(host for (host, _), share in
                                                zip(PODS.values(), held) if share),
                      'recovery_artifact': str(backup) if used_backup else None,
                      'host_custody_only': not used_backup}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f'OpenBao bootstrap failed: {error}. Protected values were not printed.',
              file=sys.stderr)
        sys.exit(1)
