import unittest
import yaml

from server.auth.modules import *

class TestAuthenticationLocal(unittest.TestCase):
    
    def setUp(self) -> None:
        self.auth = AuthenticationLocal("./tests/data/config.yml",['user'])

    def test_login_success(self):
        self.assertEqual(self.auth.login('user','abc'), 200)
    
    def test_login_failure(self):
        # Wrong password
        self.assertEqual(self.auth.login('user','Abc'), 401)
        # no user
        self.assertEqual(self.auth.login('unknown','abc'), 401)
    
    def test_login_forbidden(self):
        self.assertEqual(self.auth.login('test','test'), 403)


class TestAuthenticationUpstream(unittest.TestCase):
    def setUp(self) -> None:
        with open("./tests/data/config.yml") as f:
            data = yaml.full_load(f)
        
        self.auth =  AuthenticationUpstream(**data['modules']['/auth/upstream']['upstream'])

    def test_login_success(self):
        self.assertEqual(self.auth.login('demo',''), 200)
    
    def test_login_failure(self):
        self.assertEqual(self.auth.login('demo','Abc'), 401)



class TestAuthenticationModule(unittest.TestCase):
    def setUp(self) -> None:
        with open("./tests/data/config.yml") as f:
            self.data = yaml.full_load(f)
        
        self.auth_upstream =  AuthenticationModule(**self.data['modules']['/auth/upstream'])
        self.auth_local =  AuthenticationModule(**self.data['modules']['/auth/local'])
        self.auth_dynamic =  AuthenticationModule(**self.data['modules']['/auth/dynamic'])

    def test_login_upstream_success(self):
        self.assertEqual(self.auth_upstream.login('demo',''), 200)
    
    def test_login_upstream_failure(self):
        self.assertEqual(self.auth_upstream.login('demo','Abc'), 401)

    def test_login_local_success(self):
        self.assertEqual(self.auth_local.login('user','abc'), 200)
    
    def test_login_local_failure(self):
        self.assertEqual(self.auth_local.login('user','Abcd'), 401)

    def test_login_dynamic_success(self):
        self.assertEqual(self.auth_dynamic.login('demo',''), 200)
        self.assertEqual(self.auth_dynamic.login('user','abc'), 200)
    
    def test_login_dynamic_failure(self):
        self.assertEqual(self.auth_dynamic.login('demo','Abc'), 401)