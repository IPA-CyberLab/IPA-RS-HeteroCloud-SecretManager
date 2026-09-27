#!/usr/bin/env python3
"""Create an ephemeral Keycloak user, exercise Chromium login, then delete it."""

import argparse
import getpass
import json
import os
from pathlib import Path
import resource
import secrets
import shlex
import subprocess
import sys


CREATE = r'''
set -euo pipefail
umask 077
work=$(mktemp -d /run/heterosecrets-oidc-e2e.XXXXXX)
trap 'rm -rf "$work"' EXIT
cat >"$work/user.json"
kcadm=/opt/heteronetwork/keycloak/bin/kcadm.sh
password=$(tr -d '\r\n' </etc/heteronetwork/keycloak/bootstrap-admin.password)
KC_CLI_PASSWORD="$password" "$kcadm" config credentials --config "$work/admin.config" \
  --server http://127.0.0.1:18080 --realm master --user admin </dev/null >/dev/null
unset password
"$kcadm" create users --config "$work/admin.config" -r heterocloud -f "$work/user.json" >/dev/null
email=$(jq -er '.email' "$work/user.json")
"$kcadm" get users --config "$work/admin.config" -r heterocloud -q "email=$email" \
  | jq -er --arg email "$email" '[.[] | select(.email == $email)] | if length == 1 then .[0].id else error("user missing") end'
'''

DELETE = r'''
set -euo pipefail
umask 077
work=$(mktemp -d /run/heterosecrets-oidc-e2e.XXXXXX)
trap 'rm -rf "$work"' EXIT
read -r uuid
[[ $uuid =~ ^[0-9a-f-]{36}$ ]] || exit 2
kcadm=/opt/heteronetwork/keycloak/bin/kcadm.sh
password=$(tr -d '\r\n' </etc/heteronetwork/keycloak/bootstrap-admin.password)
KC_CLI_PASSWORD="$password" "$kcadm" config credentials --config "$work/admin.config" \
  --server http://127.0.0.1:18080 --realm master --user admin </dev/null >/dev/null
unset password
"$kcadm" delete "users/$uuid" --config "$work/admin.config" -r heterocloud >/dev/null
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-key', required=True, type=Path)
    parser.add_argument('--known-hosts', required=True, type=Path)
    parser.add_argument('--keycloak-host', required=True)
    parser.add_argument('--playwright-root', required=True, type=Path)
    parser.add_argument('--public-origin', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    sudo_password = getpass.getpass('Keycloak host sudo password: ')
    if not sudo_password or '\n' in sudo_password:
        raise RuntimeError('Invalid sudo password')
    suffix = secrets.token_hex(8)
    email = f'heterosecrets-e2e-{suffix}@example.invalid'
    password = secrets.token_urlsafe(30)
    user = {'username': email, 'email': email,
            'firstName': 'Hetero', 'lastName': 'E2E', 'enabled': True,
            'emailVerified': True, 'requiredActions': [],
            'credentials': [{'type': 'password', 'value': password,
                             'temporary': False}]}

    def remote(script, payload):
        cmd = 'sudo -kS -p ' + shlex.quote('') + ' /bin/bash -c ' + shlex.quote(script)
        result = subprocess.run([
            'ssh', '-T', '-i', str(args.ssh_key), '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', f'UserKnownHostsFile={args.known_hosts}',
            f'mizuame@{args.keycloak_host}', cmd],
            input=sudo_password.encode() + b'\n' + payload,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=90)
        if result.returncode:
            raise RuntimeError('Ephemeral Keycloak user operation failed')
        return result.stdout.strip()

    uuid = remote(CREATE, json.dumps(user).encode())
    try:
        env = os.environ.copy()
        env['HETEROSECRETS_PLAYWRIGHT_ROOT'] = str(args.playwright_root)
        test = subprocess.run(['node', str(Path(__file__).with_suffix('.mjs'))],
                              input=json.dumps({'origin': args.public_origin,
                                                'email': email,
                                                'password': password}).encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env, check=False, timeout=90)
        if test.returncode:
            raise RuntimeError('Chromium OIDC login failed: ' +
                               test.stderr.decode(errors='replace').strip())
        print(test.stdout.decode().strip())
    finally:
        remote(DELETE, uuid + b'\n')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, AssertionError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
