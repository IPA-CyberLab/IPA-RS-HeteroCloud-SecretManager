import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'scripts/configure-openbao.py'
SPEC = importlib.util.spec_from_file_location('configure_openbao', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeAPI:
    def __init__(self, response):
        self.response = response
        self.request_body = None

    def request(self, method, path, body):
        assert method == 'POST' and path == 'auth/oidc/oidc/auth_url'
        self.request_body = body
        return self.response


class OIDCAuthURLTest(unittest.TestCase):
    def test_http_200_without_auth_url_is_failure(self):
        api = FakeAPI({'data': None})
        with self.assertRaisesRegex(RuntimeError, 'has no auth_url'):
            MODULE.verify_oidc_auth_url(api, 'owner',
                                        'http://secrets.heteronetwork.internal:21444')

    def test_auth_url_must_use_the_requested_callback(self):
        origin = 'http://secrets.heteronetwork.internal:21444'
        expected = origin + '/ui/vault/auth/oidc/oidc/callback'
        api = FakeAPI({'data': {'auth_url':
            'https://keycloak.example.test/authorize?redirect_uri=' +
            'http%3A%2F%2Fsecrets.heteronetwork.internal%3A21444%2Fui%2Fvault%2Fauth%2Foidc%2Foidc%2Fcallback'}})
        MODULE.verify_oidc_auth_url(api, 'owner', origin)
        self.assertEqual(api.request_body, {'role': 'owner', 'redirect_uri': expected})

        api.response = {'data': {'auth_url':
            'https://keycloak.example.test/authorize?redirect_uri=https%3A%2F%2Fother.example.test%2Fcallback'}}
        with self.assertRaisesRegex(RuntimeError, 'invalid auth_url'):
            MODULE.verify_oidc_auth_url(api, 'owner', origin)


if __name__ == '__main__':
    unittest.main()
