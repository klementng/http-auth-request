import unittest
import os
import shutil

from server.users.database import UserDatabase
from server.users.object import User


class TestUserDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.test_data = \
"""
somekey:
- abc     # Some comment
users:
  admin:
    password: sha256:10000:abcdefghijklmnopQRSTUVWXYZ==:UuRV7et/zfAIWowdZswGbCBfArhIheeeVmAXBw7OsWo=
    roles:
    - admin
  user:
    password: text:::abc
    roles:
    - user
"""
        with open('test_db.yaml', 'w') as f:
            f.write(self.test_data)

        self.db = UserDatabase('test_db.yaml')
        self.user = User.create('test', 'password1234', ['default'])

    def tearDown(self) -> None:
        os.remove(self.db.path)

    def step_1_test_add(self):
        self.assertTrue(
            self.db.add_user(self.user)
        )
        self.assertFalse(
            self.db.add_user(self.user)
        )

        with open(self.db.path) as f:
            self.assertNotEqual(
                f.read().strip(),
                self.test_data.strip()
            ) 

    def step_2_test_get(self):

        self.assertNotEqual(
            self.db.get_user("admin"),
            None
        )

        self.assertNotEqual(
            self.db.get_user("user"),
            None
        )

        self.assertEqual(
            self.db.get_user(self.user.username),
            self.user
        )

        self.assertEqual(
            self.db.get_user("asfaserwrqwr32q4"),
            None
        )

    def step_3_test_delete(self):
        self.assertTrue(
            self.db.delete_user(self.user.username)
        )

        self.assertFalse(
            self.db.delete_user(self.user.username)
        )

    def step_4_verify(self):
        with open(self.db.path) as f:
            self.assertEqual(
                f.read().strip(),
                self.test_data.strip()
            ) 

    def _steps(self):
        for name in dir(self):  # dir() result is implicitly sorted
            if name.startswith("step"):
                yield name, getattr(self, name)

    def test_all(self):
        for name, step in self._steps():
            try:
                step()
            except Exception as e:
                self.fail(f"{step} failed ({type(e)}: {e})")
