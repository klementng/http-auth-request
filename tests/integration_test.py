import unittest
import base64
import os

import server.config

server.config.CONFIG_PATH = "tests/data/config.yml"
server.config.LOG_LEVEL = "DEBUG"

from server.core.app import app

class TestServerAuthentication(unittest.TestCase):

    def setUp(self):
        self.default_user = "user"
        self.default_pw = 'abc'

        self.admin_user = 'admin'
        self.admin_pw = 'admin'

    def _build_header(self,user,password):
        b64_str = str(base64.b64encode(f'{user}:{password}'.encode('ascii')), "utf-8")
        headers = {"Authorization": f"Basic {b64_str}"}

        return headers
        
    def test_request_auth(self):
        client = app.test_client()

        res = client.get("/")
        self.assertEqual(res.status_code, 401)
    
    def test_random_auth_header(self):
        client = app.test_client()
        headers = {"Authorization": f"qwerwerqwerwerqwerqwerweqr"}
        res = client.get("/", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_default_success(self):
        client = app.test_client()

        headers = self._build_header(self.default_user,self.default_pw)
        res = client.get("/", headers=headers)
        self.assertEqual(res.status_code, 200)

    def test_default_failure(self):
        client = app.test_client()

        headers = self._build_header("123","123")
        res = client.get("/", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_admin_success(self):
        client = app.test_client()

        headers = self._build_header(self.admin_user,self.admin_pw)
        res = client.get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 200)
    
    def test_admin_failure(self):
        client = app.test_client()

        headers = self._build_header("er","12312312312")
        res = client.get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 401)
    
    def test_admin_restricted(self):
        client = app.test_client()

        headers = self._build_header(self.default_user,self.default_pw)
        res = client.get("/auth/admin", headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_upstream_success(self):
        client = app.test_client()
        headers = self._build_header('demo','')
        res = client.get("/auth/upstream", headers=headers)
        self.assertEqual(res.status_code, 200)
    
    def test_upstream_failure(self):
        client = app.test_client()
        headers = self._build_header('demo','1234')
        res = client.get("/auth/upstream", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_session_login(self):
        client = app.test_client()

        headers = self._build_header(self.default_user,self.default_pw)
        res = client.get("/", headers=headers)
        res = client.get("/")
        self.assertEqual(res.status_code, 200)

    def test_session_logout(self):
        client = app.test_client()

        headers = self._build_header(self.default_user,self.default_pw)
        res = client.get("/", headers=headers)
        res = client.get("/?logout")
        self.assertEqual(res.status_code, 401)

if __name__ == '__main__':
    unittest.main()