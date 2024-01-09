import unittest
import base64

from server.users.object import User
from server.users.exceptions import *

class TestUserClass(unittest.TestCase):
    def setUp(self) -> None:
        pass
    
    def tearDown(self) -> None:
        pass
    
    def test_initialize_valid(self):
        user = User(
            'TEST',
            "sha256:1000:ABCD:ABCD",
            ['test', 'TEST1']
        )

        self.assertEqual(user.username,'test')
        self.assertEqual(user.roles, ['test', 'test1'])
        self.assertEqual(user.algo,'sha256')
        self.assertEqual(user.algo_it,1000)
        self.assertEqual(user.b64_salt,"ABCD")
        self.assertEqual(user.b64_hash,'ABCD')
        self.assertEqual(user.txt_password, None)


        user = User(
            'TEST',
            "txt:::abc",
            ['test', 'TEST1']
        )

        self.assertEqual(user.username,'test')
        self.assertEqual(user.roles, ['test', 'test1'])
        
        self.assertEqual(user.algo,'txt')
        self.assertEqual(user.algo_it,None)
        self.assertEqual(user.b64_salt,None)
        self.assertEqual(user.b64_hash,None)
        self.assertEqual(user.txt_password,'abc')

    
    def test_initialize_invalid(self):
        
        data =  [
            "test:1000:ABCD:ABCD",          # invalid algo
            "sha256:100asfsdf:ABCD:ABCD",   # invalid iteration
            "sha256:100:ABC:ABCD",          # invalid base64
            "sha256:100:ABCD:ABC",          # invalid base64
            "sha256:100:ABCD:ABC:::123",    # invalid format
        ]

        for d in data:
            self.assertRaises(
                UserCreateError,
                User,
                'test',d,['test']
            )

    def test_create(self):
        user = User.create(
            'test',
            'test123',
            ['role'],
            'sha256',
            10000,
            16
        )

        self.assertEqual(user.username,'test')
        self.assertEqual(user.roles, ['role'])
        self.assertEqual(user.algo,'sha256')
        self.assertEqual(user.algo_it,10000)


        user = User.create(
            'TEST',
            "abc",
            ['test', 'TEST1'],
            'text'
        )

        self.assertEqual(user.username,'test')
        self.assertEqual(user.roles, ['test', 'test1'])
        
        self.assertEqual(user.algo,'text')
        self.assertEqual(user.algo_it,None)
        self.assertEqual(user.b64_salt,None)
        self.assertEqual(user.b64_hash,None)
        self.assertEqual(user.txt_password, 'abc')


    def test_password_verify(self):
        user = User.create(
            'test',
            'test123',
            ['role'],
            'sha256',
            10000,
            16
        )

        self.assertTrue(user.verify_password('test123'))
        self.assertFalse(user.verify_password('abcd'))


        user = User.create(
            'TEST',
            "abc",
            ['test', 'TEST1'],
            'text'
        )
        
        self.assertTrue(user.verify_password('abc'))
        self.assertFalse(user.verify_password('123'))
    

    def test_export(self):

        user = User.create(
            'TEST',
            "abc",
            ['test', 'TEST1'],
            'text'
        )

        self.assertEqual(
            user.export(),
            {
                'test':{
                    'password':'text:::abc',
                    'roles': ['test','test1']
                }
            }

        )