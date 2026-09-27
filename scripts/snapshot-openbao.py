#!/usr/bin/env python3
"""Stream an OpenBao Raft snapshot into age, then copy ciphertext off-cluster.

The snapshot-only identity is obtained using a short-lived Kubernetes service
account token. Neither token is written to a file, environment or command line.
"""

import argparse
import base64
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import resource
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import time


PODS = ('openbao-0', 'openbao-1', 'openbao-2')
REPLICA_HOSTS = ('uc-k8sp4', 'uc-k8sp5', 'ichikawap1')
REMOTE_DIR = '/var/lib/heteronetwork/openbao-backups'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(argv, *, data=None, timeout=45):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode == 0, f'Command failed: {argv[0]}')
    return result.stdout


def kubectl(kubeconfig, *argv):
    return run(['kubectl', '--kubeconfig', str(kubeconfig),
                '--request-timeout=20s', *argv])


class ForwardedTLS(http.client.HTTPSConnection):
    def __init__(self, host, port, context):
        super().__init__(host, 8200, context=context, timeout=120)
        self.local_port = port

    def connect(self):
        sock = socket.create_connection(('127.0.0.1', self.local_port), timeout=120)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PortForward:
    def __init__(self, kubeconfig, pod, port):
        self.kubeconfig, self.pod, self.port = kubeconfig, pod, port
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen([
            'kubectl', '--kubeconfig', str(self.kubeconfig), '-n', 'openbao',
            'port-forward', f'pod/{self.pod}', f'{self.port}:8200',
            '--address', '127.0.0.1',
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            require(self.proc.poll() is None, 'OpenBao port-forward failed')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=0.3):
                    return self
            except OSError:
                time.sleep(0.25)
        raise RuntimeError('OpenBao port-forward timed out')

    def __exit__(self, *_):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def connection(pod, port, context):
    return ForwardedTLS(f'{pod}.openbao-internal.openbao.svc.cluster.local',
                        port, context)


def active_pod(kubeconfig, port, context):
    for pod in PODS:
        try:
            with PortForward(kubeconfig, pod, port):
                conn = connection(pod, port, context)
                try:
                    conn.request('GET', '/v1/sys/leader')
                    response = conn.getresponse()
                    require(response.status == 200, 'OpenBao leader check failed')
                    leader = json.loads(response.read())
                    if leader.get('is_self') is True:
                        return pod
                finally:
                    conn.close()
        except (OSError, RuntimeError):
            # The remaining two voters may still have Raft quorum.
            continue
    raise RuntimeError('No active OpenBao Raft leader was found')


def snapshot(kubeconfig, pod, port, context, token, recipient, target):
    temporary = target.with_name('.' + target.name + '.tmp')
    require(not target.exists() and not temporary.exists(),
            'Snapshot or incomplete temporary file already exists')
    digest = hashlib.sha256()
    total = 0
    try:
        with PortForward(kubeconfig, pod, port):
            conn = connection(pod, port, context)
            try:
                conn.request('GET', '/v1/sys/storage/raft/snapshot',
                             headers={'X-Vault-Token': token})
                response = conn.getresponse()
                require(response.status == 200,
                        f'OpenBao snapshot API returned HTTP {response.status}')
                encrypted = subprocess.Popen(
                    ['age', '-R', str(recipient), '-o', str(temporary)],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE)
                try:
                    while chunk := response.read(1024 * 1024):
                        digest.update(chunk)
                        total += len(chunk)
                        encrypted.stdin.write(chunk)
                    encrypted.stdin.close()
                    encrypted.stdin = None
                    _, error = encrypted.communicate(timeout=120)
                    require(encrypted.returncode == 0,
                            'Snapshot encryption failed: ' + error.decode(errors='replace'))
                except Exception:
                    encrypted.kill()
                    encrypted.communicate()
                    raise
            finally:
                conn.close()
        require(total > 0 and temporary.is_file(), 'OpenBao returned an empty snapshot')
        temporary.chmod(0o600)
        return temporary, digest.hexdigest(), total
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def verify_encryption(encrypted_file, age_identity, expected_digest=None):
    digest = hashlib.sha256()
    total = 0
    decrypted = subprocess.Popen(
        ['age', '-d', '-i', str(age_identity), str(encrypted_file)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    while chunk := decrypted.stdout.read(1024 * 1024):
        digest.update(chunk)
        total += len(chunk)
    require(decrypted.wait(timeout=120) == 0 and
            total > 0 and (expected_digest is None or
                           digest.hexdigest() == expected_digest),
            'Encrypted snapshot cannot be recovered with the snapshot identity')
    return total


def snapshot_token(kubeconfig, pod, port, context):
    jwt = kubectl(kubeconfig, '-n', 'openbao', 'create', 'token',
                  'openbao-snapshot', '--duration=15m').decode().strip()
    require(jwt, 'Kubernetes did not issue a snapshot service-account token')
    with PortForward(kubeconfig, pod, port):
        conn = connection(pod, port, context)
        try:
            body = json.dumps({'role': 'heterosecrets-snapshot', 'jwt': jwt}).encode()
            conn.request('POST', '/v1/auth/kubernetes/login', body=body,
                         headers={'Content-Type': 'application/json'})
            response = conn.getresponse()
            require(response.status == 200,
                    f'OpenBao Kubernetes login returned HTTP {response.status}')
            token = json.load(response)['auth']['client_token']
            require(token, 'OpenBao did not issue a snapshot token')
            return token
        finally:
            conn.close()


def inventory_host(inventory, host):
    data = json.loads(inventory.read_text())['all']
    common = data.get('vars', {})
    for group in data['children'].values():
        if host in group.get('hosts', {}):
            return {**common, **group['hosts'][host]}
    raise RuntimeError(f'Replica host {host} is missing from inventory')


def replicate(inventory, ssh_key, target, digest):
    password = os.environ.get('HNN_IAC_BECOME_PASSWORD') or getpass.getpass(
        'Replica hosts sudo password: ')
    require(password and '\n' not in password,
            'Sudo password is required in HNN_IAC_BECOME_PASSWORD for replica hosts')
    destination = f'{REMOTE_DIR}/{target.name}'
    for host in REPLICA_HOSTS:
        details = inventory_host(inventory, host)
        common = shlex.split(details.get('ansible_ssh_common_args', ''))
        remote = f"{details['ansible_user']}@{details['ansible_host']}"
        temporary = destination + '.tmp'
        script = (f'install -d -m 0700 {shlex.quote(REMOTE_DIR)}; '
                  f'if test -e {shlex.quote(destination)}; then '
                  f'cat > /dev/null; sha256sum {shlex.quote(destination)}; '
                  f'else rm -f {shlex.quote(temporary)}; '
                  f'umask 077; cat > {shlex.quote(temporary)}; '
                  f'chmod 0600 {shlex.quote(temporary)}; '
                  f'mv {shlex.quote(temporary)} {shlex.quote(destination)}; '
                  f'sha256sum {shlex.quote(destination)}; fi')
        command = ['ssh', '-T', '-i', str(ssh_key), '-o', 'IdentitiesOnly=yes',
                   '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', *common,
                   remote, "sudo -S -p '' /bin/sh -c " + shlex.quote(script)]
        transfer = subprocess.Popen(command, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            transfer.stdin.write(password.encode() + b'\n')
            with target.open('rb') as source:
                while chunk := source.read(1024 * 1024):
                    transfer.stdin.write(chunk)
            transfer.stdin.close()
            transfer.stdin = None
            output, _ = transfer.communicate(timeout=600)
        except Exception:
            transfer.kill()
            transfer.communicate()
            raise
        require(transfer.returncode == 0, f'Encrypted replica upload failed on {host}')
        require(output.split(maxsplit=1)[0] == digest.encode(),
                f'Encrypted replica checksum mismatch on {host}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--ssh-key', required=True, type=Path)
    parser.add_argument('--snapshot-identity', required=True, type=Path)
    parser.add_argument('--recovery-dir', required=True, type=Path)
    parser.add_argument('--inventory', type=Path,
                        help='Ansible inventory for three off-cluster ciphertext replicas')
    parser.add_argument('--replicate-existing', type=Path,
                        help='Replicate a previously verified age snapshot')
    parser.add_argument('--port', type=int, default=18410)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(1024 < args.port < 65535, 'Invalid local port')
    require(args.recovery_dir.is_dir() and not args.recovery_dir.is_symlink(),
            'Recovery directory is missing or linked')
    require(stat.S_IMODE(args.recovery_dir.stat().st_mode) & 0o077 == 0,
            'Recovery directory permissions are too broad')
    require(args.ssh_key.is_file() and not args.ssh_key.is_symlink() and
            stat.S_IMODE(args.ssh_key.stat().st_mode) & 0o077 == 0,
            'Operator SSH key is missing or accessible to others')
    require(args.snapshot_identity.is_file() and not args.snapshot_identity.is_symlink()
            and stat.S_IMODE(args.snapshot_identity.stat().st_mode) & 0o077 == 0,
            'Snapshot age identity is missing or accessible to others')
    recipient = args.recovery_dir / 'snapshot-age.pub'
    public = run(['age-keygen', '-y', str(args.snapshot_identity)])
    require(public.startswith(b'age1'), 'Snapshot identity is invalid')
    if recipient.exists():
        require(recipient.read_bytes() == public, 'Snapshot recipient has changed')
    else:
        recipient.write_bytes(public)
        recipient.chmod(0o600)
    if args.replicate_existing:
        target = args.replicate_existing
        require(target.parent.resolve() == args.recovery_dir.resolve() and
                target.is_file() and not target.is_symlink() and
                target.name.startswith('openbao-raft-') and target.name.endswith('.snap.age'),
                'Existing snapshot is outside the recovery directory or missing')
        size = verify_encryption(target, args.snapshot_identity)
        pod = None
    else:
        ca = kubectl(args.kubeconfig, '-n', 'openbao', 'get', 'secret',
                     'openbao-server-tls', '-o', 'jsonpath={.data.ca\\.crt}')
        require(ca, 'OpenBao TLS CA is missing')
        context = ssl.create_default_context(cadata=base64.b64decode(ca).decode())
        pod = active_pod(args.kubeconfig, args.port, context)
        token = snapshot_token(args.kubeconfig, pod, args.port, context)
        name = 'openbao-raft-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '.snap.age'
        target = args.recovery_dir / name
        temporary, raw_digest, size = snapshot(
            args.kubeconfig, pod, args.port, context, token, recipient, target)
        verify_encryption(temporary, args.snapshot_identity, raw_digest)
        with temporary.open('rb') as file:
            os.fsync(file.fileno())
        os.replace(temporary, target)
        directory = os.open(args.recovery_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    checksum = hashlib.sha256()
    with target.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
    ciphertext_digest = checksum.hexdigest()
    if args.inventory:
        require(args.inventory.is_file(), 'Ansible inventory is missing')
        replicate(args.inventory, args.ssh_key, target, ciphertext_digest)
    print(json.dumps({'snapshot': str(target), 'source_pod': pod,
                      'snapshot_bytes': size,
                      'ciphertext_replicas': list(REPLICA_HOSTS) if args.inventory else []}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f'OpenBao snapshot failed: {error}. Protected values were not printed.',
              file=sys.stderr)
        sys.exit(1)
