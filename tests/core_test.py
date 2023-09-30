import unittest
import base64
import os

os.environ["CONFIG_DIR"] = "./tests/data"
os.environ["SETTINGS_PATH"] = "./tests/data/settings.yml"
os.environ["USERS_DB_PATH"] = "./tests/data/settings.yml"


from server.core import app
from server.users import add_user,delete_user


class TestServerAuthentication(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
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
        res = self.client.get("/")
        self.assertEqual(res.status_code, 401)
    
    def test_random_auth_header(self):
        headers = {"Authorization": f"qwerwerqwerwerqwerqwerweqr"}
        res = self.client.get("/", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_default_success(self):
        headers = self._build_header(self.default_user,self.default_pw)
        res = self.client.get("/", headers=headers)
        self.assertEqual(res.status_code, 200)

    def test_default_failure(self):
        headers = self._build_header("123","123")
        res = self.client.get("/", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_admin_success(self):
        headers = self._build_header(self.admin_user,self.admin_pw)
        res = self.client.get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 200)
    
    def test_admin_failure(self):
        headers = self._build_header("er","12312312312")
        res = self.client.get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 401)
    
    def test_admin_restricted(self):
        headers = self._build_header(self.default_user,self.default_pw)
        res = self.client.get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_upstream_success(self):
        headers = self._build_header('demo','')
        res = self.client.get("/auth/upstream", headers=headers)
        self.assertEqual(res.status_code, 200)
    
    def test_upstream_failure(self):
        headers = self._build_header('demo','1234')
        res = self.client.get("/auth/upstream", headers=headers)
        self.assertEqual(res.status_code, 401)
    

if __name__ == '__main__':
    unittest.main()
