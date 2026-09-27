#!/usr/bin/env python3
"""Exercise an encrypted snapshot on a loopback-only, disposable OpenBao process.

The second process runs inside an existing dedicated OpenBao Pod on uc-k8sp1.
It is not joined to production Raft, has no Service or cluster-accessible
listener, and writes only to its own temporary directory. Cleanup is automatic.
"""

import argparse
import base64
import http.client
import importlib.util
import json
import os
from pathlib import Path
import resource
import secrets
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('configure_openbao', ROOT / 'scripts/configure-openbao.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
POD = 'openbao-1'
PORT = 18430
PROBE = 'secret/data/system/restore-probe'


def run(argv, *, data=None, timeout=45):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} failed')
    return result.stdout


def kube(kubeconfig, *args, data=None, timeout=45):
    return run(['kubectl', '--kubeconfig', str(kubeconfig), '-n', 'openbao',
                *args], data=data, timeout=timeout)


def req(method, path, body=None, token=None, statuses=(200, 204)):
    conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=30)
    headers = {}
    if token:
        headers['X-Vault-Token'] = token
    if isinstance(body, dict):
        body = json.dumps(body, separators=(',', ':')).encode()
        headers['Content-Type'] = 'application/json'
    elif body is not None:
        headers['Content-Type'] = 'application/octet-stream'
    try:
        conn.request(method, '/v1/' + path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        if response.status not in statuses:
            raise RuntimeError(f'isolated OpenBao {path} returned HTTP {response.status}')
        return json.loads(data) if data else {}
    finally:
        conn.close()


def source_api(args, root):
    ca_b64 = kube(args.kubeconfig, 'get', 'secret', 'openbao-server-tls',
                  '-o', 'jsonpath={.data.ca\\.crt}')
    temporary = tempfile.TemporaryDirectory(prefix='openbao-restore-ca-', dir='/dev/shm')
    ca = Path(temporary.name) / 'ca.crt'
    ca.write_bytes(base64.b64decode(ca_b64))
    return temporary, MODULE.API('openbao-0', 18431, ca, root)


def prepare(args, root):
    marker = secrets.token_hex(24)
    with MODULE.Forward(args.kubeconfig, 'openbao-0', 18431):
        temporary, api = source_api(args, root)
        try:
            api.request('POST', PROBE, {'data': {'marker': marker}})
            assert api.request('GET', PROBE)['data']['data']['marker'] == marker
        finally:
            temporary.cleanup()
    target = args.recovery_dir / 'restore-probe.json'
    with target.open('x') as stream:
        json.dump({'marker': marker}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    target.chmod(0o600)
    print('restore probe written; take a new encrypted snapshot before --restore')


def restore(args, shares):
    marker = json.loads((args.recovery_dir / 'restore-probe.json').read_text())['marker']
    snapshot = run(['age', '-d', '-i', str(args.snapshot_identity),
                    str(args.snapshot)], timeout=120)
    if not (1000 < len(snapshot) < 64 * 1024 * 1024):
        raise RuntimeError('snapshot size is outside the bounded restore-test range')

    config = (ROOT / 'deploy/restore-test/config.hcl').read_bytes()
    script = (b'set -eu; umask 077; test ! -e /tmp/openbao-restore-test; '
              b'mkdir -m 0700 /tmp/openbao-restore-test; '
              b'mkdir -m 0700 /tmp/openbao-restore-test/raft; '
              b'cat > /tmp/openbao-restore-test/config.hcl')
    kube(args.kubeconfig, 'exec', '-i', POD, '--', '/bin/sh', '-c', script.decode(),
         data=config)
    try:
        kube(args.kubeconfig, 'exec', POD, '--', '/bin/sh', '-c',
             'cd /tmp/openbao-restore-test; '
             '/usr/bin/bao server -config=config.hcl </dev/null >server.log 2>&1 & '
             'echo $! >pid')
        with MODULE.Forward(args.kubeconfig, POD, PORT, target_port=18200):
            last_error = None
            for _ in range(240):
                try:
                    status = req('GET', 'sys/init')
                    break
                except (OSError, RuntimeError) as exc:
                    last_error = str(exc)
                    time.sleep(.25)
            else:
                raise RuntimeError(f'isolated OpenBao did not accept API calls: {last_error}')
            if status['initialized']:
                raise RuntimeError('isolated OpenBao unexpectedly initialized')
            generated = req('PUT', 'sys/init',
                            {'secret_shares': 3, 'secret_threshold': 2})
            for share in generated['keys_base64'][:2]:
                try:
                    seal = req('PUT', 'sys/unseal', {'key': share})
                except RuntimeError as exc:
                    raise RuntimeError(f'isolated initial unseal failed: {exc}') from exc
            if seal['sealed']:
                raise RuntimeError('isolated OpenBao did not unseal')
            req('POST', 'sys/storage/raft/snapshot-force', snapshot,
                generated['root_token'])
            jwt = kube(args.kubeconfig, 'create', 'token', 'openbao',
                       '--duration=10m').decode().strip()
            for _ in range(30):
                try:
                    seal = req('GET', 'sys/seal-status')
                except (OSError, RuntimeError):
                    time.sleep(1)
                    continue
                if seal['sealed']:
                    for share in shares:
                        try:
                            seal = req('PUT', 'sys/unseal', {'key': share})
                        except RuntimeError as exc:
                            raise RuntimeError(f'isolated restored unseal failed: {exc}') from exc
                    if seal['sealed']:
                        time.sleep(1)
                        continue
                try:
                    auth = req('POST', 'auth/kubernetes/login',
                               {'role': 'heterosecrets-restore-probe', 'jwt': jwt})
                    probe_token = auth['auth']['client_token']
                    restored = req('GET', PROBE, token=probe_token)
                    if restored['data']['data']['marker'] != marker:
                        raise RuntimeError('restored secret differs from the probe')
                    roles = req('GET', 'auth/oidc/role/users', token=probe_token)['data']
                    if 'heterosecrets-user' not in roles.get('token_policies', roles.get('policies', [])):
                        raise RuntimeError('restored OIDC role is missing')
                    print(json.dumps({'restore_verified': True,
                                      'probe_matches': True,
                                      'kv_v2': True,
                                      'oidc_role': True}))
                    return
                except (OSError, RuntimeError):
                    time.sleep(1)
            raise RuntimeError('restored OpenBao did not return the probe and policies')
    except Exception:
        try:
            log = kube(args.kubeconfig, 'exec', POD, '--', '/bin/sh', '-c',
                       'tail -n 18 /tmp/openbao-restore-test/server.log 2>/dev/null || true')
            print('isolated OpenBao startup diagnostics: ' +
                  log.decode(errors='replace')[-1800:], file=sys.stderr)
        except Exception:
            pass
        raise
    finally:
        kube(args.kubeconfig, 'exec', POD, '--', '/bin/sh', '-c',
             'if test -f /tmp/openbao-restore-test/pid; then '
             'kill "$(cat /tmp/openbao-restore-test/pid)" 2>/dev/null || true; fi; '
             'rm -rf /tmp/openbao-restore-test', timeout=45)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--ssh-key', required=True, type=Path)
    parser.add_argument('--recovery-identity', type=Path,
                        help='Dedicated age identity for the encrypted init artifact')
    parser.add_argument('--recovery-dir', required=True, type=Path)
    parser.add_argument('--snapshot-identity', type=Path)
    parser.add_argument('--snapshot', type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    init = json.loads(run(['age', '-d', '-i',
                           str(args.recovery_identity or args.ssh_key),
                           str(args.recovery_dir / 'openbao-init.json.age')]))
    shares = init['keys_base64'][:2]
    if args.prepare:
        prepare(args, init['root_token'])
    else:
        assert args.snapshot and args.snapshot_identity
        restore(args, shares)


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, KeyError, ValueError, OSError, RuntimeError) as exc:
        print(f'restore verification failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
