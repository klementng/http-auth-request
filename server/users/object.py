import base64
import binascii
import hashlib
import secrets
from typing import Iterable

from server.users.exceptions import *


class User:

    TEXT_FORMATS = ['txt', 'text', 'plaintext']

    def __init__(self, username: str, db_password: str, roles: Iterable) -> None:
        """
        The function initializes an object with a username, database password, and roles, and then parses
        the database password.
        
        Args:
          username (str): The `username` parameter is a string that represents the username of the user. It
        is expected to be a non-empty string.
          db_password (str): The `db_password` parameter is a string that represents the password stored in
        the database.
          roles (Iterable): The `roles` parameter is an iterable object that contains the roles associated
        with the user.
        """

        self.username: str = username.lower().strip()
        self.roles: list = [r.lower().strip() for r in roles]

        self.algo, self.algo_it, self.b64_salt, self.b64_hash, self.txt_password = self._parse_db_password(
            db_password
        )

    def __str__(self) -> str:
        return f"""
username: {self.username}
roles:   {self.roles}

algo: {self.algo}
algo_it: {self.algo_it}
salted: {self.b64_hash != None}
"""

    def __eq__(self, other) : 
        try:
            return \
                self.username == other.username and \
                self.roles == other.roles and \
                self.algo == other.algo and \
                self.algo_it == other.algo_it and \
                self.b64_salt == other.b64_salt and \
                self.b64_hash == other.b64_hash and \
                self.txt_password == other.txt_password
        
        except:
            return False
    
    @classmethod
    def create(cls, username: str, password: str, roles: Iterable = ['default'], algo: str = 'sha256', iterations: int = 10000, salt_n_bytes: int = 16):
        """
        The function `create` takes in a username, password, roles, algorithm, iterations, and salt_n_bytes,
        and returns an instance of a class with the provided data.
        
        Args:
          username (str): The `username` parameter is a string that represents the username of the user you
        want to create.
          password (str): The `password` parameter is a string that represents the user's password.
          roles (Iterable): The `roles` parameter is an iterable (such as a list or tuple) that specifies
        the roles associated with the user. By default, if no roles are provided, it will be set to
        `['default']`. Roles can be used to define different levels of access or permissions for the user
        within
          algo (str): The `algo` parameter is a string that specifies the hashing algorithm to be used for
        password hashing. Defaults to sha256
          iterations (int): The `iterations` parameter specifies the number of iterations to be used in the
        password hashing algorithm. It determines the computational cost of hashing the password. Defaults to 10000
          salt_n_bytes (int): The `salt_n_bytes` parameter specifies the number of bytes to be used for
        generating the salt value. Defaults to 16
        
        Returns:
          an instance of the 'User' class
        """

        if algo in cls.TEXT_FORMATS:
            data = f"{algo}:::{password}"

        else:
            b64str_hash, b64str_salt = cls._hash_password(
                algo,
                iterations,
                password.encode(),
                secrets.token_bytes(salt_n_bytes)
            )

            data = f"{algo}:{iterations}:{b64str_salt}:{b64str_hash}"
        
        return cls(username, data, roles)

    @classmethod
    def _parse_db_password(cls, db_password: str):
        """
        The function `_parse_db_password` parses a database password string and returns the algorithm,
        iterations, salt, hash, and text password.
        
        Args:
          db_password (str): The `db_password` parameter is a string that represents a stored password in a
        specific format in the database. 
        The format is expected to be `'algo:iterations:b64(salt):b64(algo(salt+password))'
        
        Returns:
          The `_parse_db_password` method returns a tuple containing the following values:
        algo, it, b64str_salt, b64str_hash, plaintext_password(stored in plaintext password)

        Raises:
            UserCreateError: Occurs when function received an improperly formatted string
       
         """
        pw_split = db_password.split(":")

        if len(pw_split) != 4:
            raise UserCreateError(
                "Unrecognized stored data format. Expected 'algo:iterations:b64(salt):b64(algo(salt+password))'"
            )

        algo = pw_split[0].lower()

        if algo in cls.TEXT_FORMATS:
            text_password = pw_split[3]

            if text_password == '':
                raise UserCreateError(f"password cannot be empty")

            return algo, None, None, None, text_password

        else:

            if algo not in hashlib.algorithms_available:
                raise UserCreateError(
                    f"hashing algorithms: '{algo}' is not supported ")

            try:
                it = int(pw_split[1])
                b64str_salt = pw_split[2]
                b64str_hash = pw_split[3]

                base64.b64decode(b64str_salt, validate=True)
                base64.b64decode(b64str_hash, validate=True)

                assert b64str_hash != ''
                
                return algo, it, b64str_salt, b64str_hash, None

            except (binascii.Error, ValueError) as e:
                raise UserCreateError(f"Invalid data! Unable to parse data... {e}")
            
            except AssertionError as e:
                raise UserCreateError(f"password hash cannot be empty")

    @classmethod
    def _hash_password(cls, algo: str, iterations: int, password: bytes, salt: bytes):
        """
        The function `_hash_password` takes in an algorithm, number of iterations, password, and salt, and
        returns the base64 encoded salt and hash of the password.
        
        Args:
          algo (str): The `algo` parameter represents the hashing algorithm to be used.
          iterations (int): The "iterations" parameter represents the number of iterations or rounds of the
        hashing algorithm
          password (bytes): The `password` parameter is the user's password that needs to be hashed. It
        should be provided as a bytes object.
          salt (bytes): The salt is a associated with the password
        
        Returns:
          a tuple containing two strings: 'b64str_hash' and `b64str_salt`.
        """
        pw_hash = hashlib.pbkdf2_hmac(algo, password, salt, iterations)

        b64str_salt = str(base64.b64encode(salt), 'utf-8')
        b64str_hash = str(base64.b64encode(pw_hash), 'utf-8')

        return b64str_hash, b64str_salt

    def hash_password(self, password: str):
        """
        The function `hash_password` takes a password as input.
        
        Args:
          password (str): The `password` parameter is a string that represents the user's password.
        
        Returns:
          the hashed password in base64 formatted string format.
        """
        
        if self.algo in self.TEXT_FORMATS:
            raise UserHashingError(f"Hashing method is not implemented when algorithm is '{self.algo}'")        
        
        return self._hash_password(
            self.algo,
            self.algo_it,  # type: ignore
            password.encode(),
            base64.b64decode(self.b64_salt)  # type: ignore
        )[0]

    def export(self):
        """
        The `export` function returns a dictionary containing the username, password, and roles.
        
        Returns:
          a dictionary with the following structure:
           ``` {
                self.username: {
                    'password': db_password,
                    'roles': self.roles
                }
            }
          ```
        """

        if self.algo in self.TEXT_FORMATS:
            db_password = f"{self.algo}:::{self.txt_password}"
        else:
            db_password = f"{self.algo}:{self.algo_it}:{self.b64_salt}:{self.b64_hash}"

        return {
            self.username: {
                'password': db_password,
                'roles': self.roles
            }
        }

    def change_password(self, new_password):
        """
        The `change_password` function updates the password.
        
        Args:
          new_password: The `new_password` parameter is the new password that the user wants to set.
        """
        if self.algo in self.TEXT_FORMATS:
            self.txt_password = new_password
        else:
            self.b64_hash = self.hash_password(new_password)

    def verify_role(self, role: str | list):
        """
        The function `verify_role` checks if a given role or list of roles is present is part of the user roles list
        
        Args:
          role (str | list): The `role` parameter can be either a string or a list.
        
        Returns:
          a boolean value.
        """
        if isinstance(role, str):
            return role in self.roles
        
        elif isinstance(role, list):
            return any(True for r in self.roles if r in role)
        
        else:
            raise TypeError

    def verify_password(self, password: str) -> bool:
        """
        The function verifies a password by comparing it to a stored password or by hashing it and
        comparing it to a stored hash.
        
        Args:
          password (str): The `password` parameter is a string that represents the password that needs
        to be verified.
        
        Returns:
          a boolean value. If successful else False
        """
        if self.algo in self.TEXT_FORMATS:
            return self.txt_password == password
        else:
            return self.b64_hash == self.hash_password(password)