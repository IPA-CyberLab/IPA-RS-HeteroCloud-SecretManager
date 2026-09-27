import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'scripts/configure-openbao.py'
SPEC = importlib.util.spec_from_file_location('configure_openbao', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeAPI:
    def __init__(self):
        self.writes = {}

    def request(self, method, path, body=None, allow=(200, 204)):
        if method == 'GET' and path == 'sys/mounts':
            return {'data': {'secret/': {'type': 'kv', 'options': {'version': '2'}}}}
        if method == 'GET' and path == 'sys/auth':
            return {'data': {'kubernetes/': {'type': 'kubernetes',
                                            'accessor': 'auth_kubernetes_1234'}}}
        self.writes[(method, path)] = body
        return {}


class FlashAuthTest(unittest.TestCase):
    def test_workload_is_read_only_and_scoped_to_its_service_account(self):
        api = FakeAPI()
        MODULE.ensure_flash_auth(api)
        policy = api.writes[('PUT', 'sys/policies/acl/heterosecrets-flash-workload')]['policy']
        self.assertIn('secret/data/flash/{{identity.entity.aliases.auth_kubernetes_1234.metadata.service_account_name}}/*', policy)
        self.assertIn('capabilities = ["read"]', policy)
        self.assertNotIn('update', policy)
        role = api.writes[('POST', 'auth/kubernetes/role/heterosecrets-flash-workload')]
        self.assertEqual(role['bound_service_account_namespaces'], ['heterocloud-flash-workloads'])
        api_role = api.writes[('POST', 'auth/kubernetes/role/heterosecrets-flash-api')]
        self.assertEqual(api_role['bound_service_account_names'], ['heterocloud-heterocloud'])
        self.assertEqual(api_role['bound_service_account_namespaces'], ['heterocloud'])


if __name__ == '__main__':
    unittest.main()
