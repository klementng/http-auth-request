import unittest
import base64
import os
import secrets

os.environ["CONFIG_DIR"] = "./tests/data"
os.environ["SETTINGS_PATH"] = "./tests/data/settings.yml"

os.environ["CACHE_TTL"] = os.getenv("CACHE_TTL", '60')
os.environ["LOG_LEVEL"] = os.getenv("LOG_LEVEL", "DEBUG")

os.environ["FLASK_SESSION_COOKIE_DOMAIN"] = os.getenv("FLASK_SESSION_COOKIE_DOMAIN","")
os.environ["FLASK_SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY",secrets.token_hex(16))


from server.core import app
from server.users import add_user,delete_user


class TestServerAuthentication(unittest.TestCase):

    def setUp(self):
        self.default_user = "test"
        self.default_pw = 'test'

        self.admin_user = 'test_admin'
        self.admin_pw = 'test_admin'

        add_user(self.admin_user,self.admin_pw)
        add_user(self.default_user,self.default_pw)
    
    def tearDown(self):
        delete_user("test")
        delete_user("test_admin")
    
    def _build_header(self,user,password):
        b64_str = str(base64.b64encode(f'{user}:{password}'.encode('ascii')), "utf-8")
        headers = {"Authorization": f"Basic {b64_str}"}

        return headers
    
    def test_request_auth(self):
        res = app.test_client().get("/")
        self.assertEqual(res.status_code, 401)
    
    def test_random_auth_header(self):
        headers = {"Authorization": f"qwerwerqwerwerqwerqwerweqr"}
        res = app.test_client().get("/", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_default_success(self):
        headers = self._build_header(self.default_user,self.default_pw)
        res = app.test_client().get("/", headers=headers)
        self.assertEqual(res.status_code, 200)

    def test_default_failure(self):
        headers = self._build_header("123","123")
        res = app.test_client().get("/", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_admin_success(self):
        headers = self._build_header(self.admin_user,self.admin_pw)
        res = app.test_client().get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 200)
    
    def test_admin_failure(self):
        headers = self._build_header("er","12312312312")
        res = app.test_client().get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 401)
    
    def test_admin_restricted(self):
        headers = self._build_header(self.default_user,self.default_pw)
        res = app.test_client().get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_upstream_success(self):
        headers = self._build_header('demo','')
        res = app.test_client().get("/auth/upstream", headers=headers)
        self.assertEqual(res.status_code, 200)
    
    def test_upstream_failure(self):
        headers = self._build_header('demo','1234')
        res = app.test_client().get("/auth/upstream", headers=headers)
        self.assertEqual(res.status_code, 401)
        
    def test_cookie_login(self):
        headers = self._build_header(self.default_user,self.default_pw)
        client = app.test_client(use_cookies=True)
        res = client.get("/auth", headers=headers)
        self.assertEqual(res.status_code, 200)

        res = client.get("/auth")
        self.assertEqual(res.status_code,200)



if __name__ == '__main__':
    unittest.main()
