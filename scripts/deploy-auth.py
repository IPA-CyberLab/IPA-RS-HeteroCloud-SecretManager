#!/usr/bin/env python3
"""Configure Keycloak client and OpenBao without persisting exchanged secrets."""

import argparse
import getpass
import json
import os
from pathlib import Path
import resource
import shlex
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--ssh-key', type=Path, required=True)
    parser.add_argument('--known-hosts', type=Path, required=True)
    parser.add_argument('--keycloak-host', required=True)
    parser.add_argument('--recovery-dir', type=Path, required=True)
    parser.add_argument('--public-origin', required=True)
    parser.add_argument('--oidc-issuer', required=True)
    parser.add_argument('--owner-email', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    script = (Path(__file__).parent / 'reconcile-keycloak-client.sh').read_bytes()
    password = getpass.getpass('Keycloak host sudo password: ')
    if not password or '\n' in password:
        raise RuntimeError('Invalid sudo password')
    remote_command = ' '.join(shlex.quote(part) for part in [
        'sudo', '-S', '-p', '', 'env',
        f'HETEROSECRETS_PUBLIC_ORIGIN={args.public_origin}',
        f'HETEROSECRETS_OIDC_ISSUER={args.oidc_issuer}',
        f'HETEROSECRETS_OWNER_EMAIL={args.owner_email}',
        '/bin/bash', '-s',
    ])
    remote = [
        'ssh', '-T', '-i', str(args.ssh_key), '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', f'UserKnownHostsFile={args.known_hosts}',
        f'mizuame@{args.keycloak_host}',
        remote_command,
    ]
    result = subprocess.run(remote, input=password.encode() + b'\n' + script,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=90)
    del password
    if result.returncode:
        # Keycloak diagnostics can contain private configuration. Keep them local.
        raise RuntimeError('Remote Keycloak client reconciliation failed')
    client = json.loads(result.stdout)
    assert client['client_id'] and client['client_secret'] and client['owner_subject']
    command = [sys.executable, str(Path(__file__).parent / 'configure-openbao.py'),
               '--kubeconfig', str(args.kubeconfig), '--ssh-key', str(args.ssh_key),
               '--recovery-dir', str(args.recovery_dir),
               '--public-origin', args.public_origin]
    configured = subprocess.run(command, input=json.dumps(client).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=180)
    if configured.returncode:
        raise RuntimeError('OpenBao configuration failed: ' +
                           configured.stderr.decode(errors='replace').strip())
    print(configured.stdout.decode().strip())


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
