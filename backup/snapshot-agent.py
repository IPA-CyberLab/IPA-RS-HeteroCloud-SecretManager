#!/usr/bin/env python3
"""Stream a TLS-verified OpenBao Raft snapshot into age on replicated storage."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import ssl
import subprocess
import sys
import time

NAMESPACE = 'openbao'
PODS = tuple(f'openbao-{n}.openbao-internal.{NAMESPACE}.svc.cluster.local'
             for n in range(3))
BACKUP_DIR = Path('/backups')
CA = '/etc/openbao-ca/ca.crt'
RECIPIENT = Path('/etc/age-recipient/recipient')
JWT = Path('/var/run/secrets/kubernetes.io/serviceaccount/token')
ROLE = 'heterosecrets-snapshot'
RETENTION_SECONDS = 35 * 86400


def request(host, method, path, context, *, token=None, body=None, stream=False):
    conn = http.client.HTTPSConnection(host, 8200, context=context, timeout=120)
    headers = {}
    if token:
        headers['X-Vault-Token'] = token
    if body is not None:
        headers['Content-Type'] = 'application/json'
        body = json.dumps(body, separators=(',', ':')).encode()
    conn.request(method, '/v1/' + path, body=body, headers=headers)
    response = conn.getresponse()
    if response.status != 200:
        response.read()
        conn.close()
        raise RuntimeError(f'OpenBao {path} returned HTTP {response.status}')
    if stream:
        return conn, response
    payload = json.load(response)
    conn.close()
    return payload


def leader(context):
    for host in PODS:
        try:
            result = request(host, 'GET', 'sys/leader', context)
        except (OSError, RuntimeError):
            continue
        if result.get('is_self'):
            return host
    raise RuntimeError('No reachable OpenBao leader')


def snapshot(host, context, token, recipient):
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    target = BACKUP_DIR / f'openbao-raft-{stamp}.snap.age'
    temporary = BACKUP_DIR / f'.openbao-raft-{stamp}-{os.getpid()}.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    conn = None
    encrypted = None
    count = 0
    try:
        conn, response = request(host, 'GET', 'sys/storage/raft/snapshot',
                                 context, token=token, stream=True)
        encrypted = subprocess.Popen(['age', '-r', recipient, '-o', str(temporary)],
                                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        while chunk := response.read(1024 * 1024):
            encrypted.stdin.write(chunk)
            count += len(chunk)
        encrypted.stdin.close()
        encrypted.stdin = None
        if encrypted.wait(timeout=120) != 0 or count == 0:
            raise RuntimeError('Snapshot encryption failed or source was empty')
        with temporary.open('rb') as ciphertext:
            os.fsync(ciphertext.fileno())
        os.replace(temporary, target)
        directory = os.open(BACKUP_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return target, count
    finally:
        if conn:
            conn.close()
        if encrypted and encrypted.poll() is None:
            encrypted.kill()
            encrypted.wait()
        temporary.unlink(missing_ok=True)


def prune(now):
    pattern = re.compile(r'^openbao-raft-\d{8}T\d{6}Z\.snap\.age$')
    for path in BACKUP_DIR.iterdir():
        if (pattern.fullmatch(path.name) and not path.is_symlink()
                and path.is_file() and now - path.stat().st_mtime > RETENTION_SECONDS):
            path.unlink()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    recipient = RECIPIENT.read_text().strip()
    if not re.fullmatch(r'age1[0-9a-z]{58}', recipient):
        raise RuntimeError('Invalid age recipient')
    context = ssl.create_default_context(cafile=CA)
    host = leader(context)
    login = request(host, 'POST', 'auth/kubernetes/login', context,
                    body={'role': ROLE, 'jwt': JWT.read_text().strip()})
    token = login['auth']['client_token']
    target, count = snapshot(host, context, token, recipient)
    prune(time.time())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(json.dumps({'file': target.name, 'plaintext_bytes': count,
                      'ciphertext_sha256': digest}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        # Never log a token, JWT, plaintext snapshot or server response body.
        print(f'OpenBao snapshot failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
