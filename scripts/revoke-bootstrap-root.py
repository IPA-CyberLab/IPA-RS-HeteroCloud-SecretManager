#!/usr/bin/env python3
"""Revoke the one-time bootstrap root token after OIDC and restore verification."""

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import resource
import ssl
import subprocess
import sys
import tempfile


SOURCE = Path(__file__).with_name('configure-openbao.py')
SPEC = importlib.util.spec_from_file_location('configure_openbao', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--recovery-identity', required=True, type=Path)
    parser.add_argument('--recovery-dir', required=True, type=Path)
    parser.add_argument('--port', type=int, default=18440)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    encrypted = args.recovery_dir / 'openbao-init.json.age'
    root = json.loads(MODULE.command(['age', '-d', '-i', str(args.recovery_identity),
                                      str(encrypted)]))['root_token']
    ca_b64 = MODULE.command(['kubectl', '--kubeconfig', str(args.kubeconfig),
                             '-n', 'openbao', 'get', 'secret', 'openbao-server-tls',
                             '-o', 'jsonpath={.data.ca\\.crt}'])
    with tempfile.TemporaryDirectory(prefix='heterosecrets-revoke-', dir='/dev/shm') as tmp:
        ca = Path(tmp) / 'ca.crt'
        ca.write_bytes(base64.b64decode(ca_b64))
        context = ssl.create_default_context(cafile=str(ca))
        for pod in MODULE.PODS:
            with MODULE.Forward(args.kubeconfig, pod, args.port):
                conn = MODULE.TLSConnection(
                    f'{pod}.openbao-internal.openbao.svc.cluster.local',
                    args.port, context)
                try:
                    conn.request('GET', '/v1/sys/leader')
                    response = conn.getresponse()
                    if response.status != 200 or not json.load(response)['is_self']:
                        continue
                finally:
                    conn.close()
                api = MODULE.API(pod, args.port, ca, root)
                try:
                    api.request('GET', 'auth/token/lookup-self')
                except RuntimeError as exc:
                    if 'HTTP 403' in str(exc):
                        print(json.dumps({'bootstrap_root_revoked': True,
                                          'already_revoked': True}))
                        return
                    raise
                owner = api.request('GET', 'auth/oidc/role/owner')['data']
                if (not owner.get('bound_claims', {}).get('sub') or
                        'heterosecrets-owner' not in owner.get('token_policies', [])):
                    raise RuntimeError('Bound owner OIDC role is missing')
                users = api.request('GET', 'auth/oidc/role/users')['data']
                if 'heterosecrets-user' not in users.get('token_policies', []):
                    raise RuntimeError('Default user OIDC role is missing')
                probe = api.request('GET',
                                    'auth/kubernetes/role/heterosecrets-restore-probe')['data']
                if 'heterosecrets-restore-probe' not in probe.get('token_policies', []):
                    raise RuntimeError('Isolated restore identity is missing')
                if args.check_only:
                    print(json.dumps({'ready_to_revoke_bootstrap_root': True,
                                      'owner_oidc_bound': True,
                                      'restore_identity': True}))
                    return
                api.request('POST', 'auth/token/revoke-self', allow=(204,))
                try:
                    api.request('GET', 'auth/token/lookup-self')
                except RuntimeError as exc:
                    if 'HTTP 403' in str(exc):
                        print(json.dumps({'bootstrap_root_revoked': True,
                                          'already_revoked': False}))
                        return
                    raise
                raise RuntimeError('Bootstrap root token still works after revocation')
        raise RuntimeError('No active OpenBao leader')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print(f'Bootstrap root revocation failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
