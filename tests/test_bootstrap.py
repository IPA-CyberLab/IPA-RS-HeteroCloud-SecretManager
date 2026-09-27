"""Check that host-only recovery works with one custodian unavailable."""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/bootstrap-openbao.py'
SPEC = importlib.util.spec_from_file_location('bootstrap_openbao', SCRIPT)
BOOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOT)


class TwoOfThreeRecovery(unittest.TestCase):
    def run_bootstrap(self, available_shares):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'operator.key'
            key.write_text('test-only')
            key.chmod(0o600)
            known = root / 'known_hosts'
            known.write_text('test-only')
            recovery = root / 'recovery'
            argv = [str(SCRIPT), '--kubeconfig', str(root / 'kubeconfig'),
                    '--ssh-key', str(key), '--known-hosts', str(known),
                    '--recovery-dir', str(recovery)]

            class FakeAPI:
                available = ['openbao-1', 'openbao-2']

                def __init__(self, *_):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    pass

                def request(self, _pod, path):
                    assert path == 'sys/init'
                    return {'initialized': True}

            def host_share(_args, address):
                share = available_shares.get(address)
                if share is None:
                    raise RuntimeError('custodian unreachable')
                return share

            output = io.StringIO()
            with mock.patch.object(sys, 'argv', argv), \
                 mock.patch.dict(os.environ, {'HNN_IAC_BECOME_PASSWORD': 'test-only'}), \
                 mock.patch.object(BOOT, 'kubectl', return_value=base64.b64encode(b'ca')), \
                 mock.patch.object(BOOT, 'BaoAPI', FakeAPI), \
                 mock.patch.object(BOOT, 'host_share', side_effect=host_share), \
                 mock.patch.object(BOOT, 'unseal') as unseal, \
                 contextlib.redirect_stdout(output):
                BOOT.main()
            return json.loads(output.getvalue()), unseal.call_count

    def test_recovers_with_two_distinct_host_shares(self):
        shares = {
            '163.220.236.51': base64.b64encode(b'a' * 32) + b'\n',
            '163.220.236.53': base64.b64encode(b'b' * 32) + b'\n',
        }
        result, unseal_calls = self.run_bootstrap(shares)
        self.assertEqual(result['unsealed'], ['openbao-1', 'openbao-2'])
        self.assertEqual(result['host_custodians'], ['uc-k8s3p', 'uc-k8sp1'])
        self.assertTrue(result['host_custody_only'])
        self.assertEqual(unseal_calls, 2)

    def test_rejects_only_one_share(self):
        shares = {'163.220.236.51': base64.b64encode(b'a' * 32) + b'\n'}
        with self.assertRaisesRegex(RuntimeError, 'At least two distinct'):
            self.run_bootstrap(shares)


if __name__ == '__main__':
    unittest.main()
