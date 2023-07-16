"""Module for managing local users.

This modules provide 4 basic function: 
  - adding users
  - delete users
  - modifying users password 
  - verify users password 

"""
import os
import sqlite3
import base64
import hashlib
import secrets
import logging
import ruamel.yaml

from ruamel.yaml.scanner import ScannerError
from server.shared import ConfigurationError

logger = logging.getLogger(__name__)

yaml = ruamel.yaml.YAML()
yaml.preserve_quotes = True
yaml.width = 4096

CONFIG_DIR = os.environ["CONFIG_DIR"]
SETTINGS_PATH = os.environ["SETTINGS_PATH"]

USERS_DB_MODE = os.getenv("USERS_DB_MODE", 'YAML').upper()
USERS_DB_PATH = os.getenv("USERS_DB_PATH")

if USERS_DB_MODE not in ['YAML', "SQLITE3"]:
    raise EnvironmentError("USERS_DB_MODE can only be 'YAML' or 'SQLITE3'")


if USERS_DB_PATH == None:
    if USERS_DB_MODE == "SQLITE3":
        USERS_DB_PATH = os.path.join(CONFIG_DIR, "users.db")

    if USERS_DB_MODE == 'YAML':
        USERS_DB_PATH = SETTINGS_PATH

os.makedirs(os.path.dirname(USERS_DB_PATH), exist_ok=True)


def _load_file() -> dict | tuple[sqlite3.Connection, sqlite3.Cursor]:
    """
    Load the users database from file

    Returns:
        YAML mode: returns dictionary object of parsed yaml file with key 'users' set
        SQLITE3 mode: return a sqlite3.Connection, sqlite3.Cursor

    Raises:
        ConfigurationError: users is not defined properly in YAML file
        ScannerError: Failed to parse YAML file
        sqlite3.DatabaseError: unable to connect to database
    """

    if USERS_DB_MODE == 'YAML':

        with open(USERS_DB_PATH) as f:
            data = yaml.load(f)

            if data == None:
                data = {}
                data.setdefault('users', {})

            if data.get('users') == None:
                data['users'] = {}

            if not isinstance(data.get('users'), dict):
                logger.critical("'users' is not a dictionary")
                raise ConfigurationError("'users' is not a dictionary")

        return data

    if USERS_DB_MODE == 'SQLITE3':
        con = sqlite3.connect(USERS_DB_PATH)
        sql = """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT
            ) WITHOUT ROWID;
        """
        cur = con.cursor()
        cur.execute(sql)
        con.commit()

        return con, cur


def _get_password(username: str) -> str:
    """
    Get password or hash string for a user 

    Returns:
        password or hash string

    Raises:
        ConfigurationError: users is not defined properly in YAML file
        ScannerError: Failed to parse YAML file
        sqlite3.DatabaseError: unable to connect to database
    """
    if USERS_DB_MODE == 'YAML':
        data = _load_file()
        users = data['users']

        return users.get(username)

    if USERS_DB_MODE == 'SQLITE3':
        con, cur = _load_file()
        sql = "SELECT password FROM users WHERE username=:username"
        res = cur.execute(sql, {"username": username}).fetchone()

        return res[0] if res != None else res


def _update_users(username: str, password: str, algo: str = "sha256", salt_bytes: int = 16, iterations: int = 10000) -> bool:
    """
    Add or update a user in the database 

    Args:
        username: unique username of user
        password: password for user
        algo: hashing algorithm, defaults 'sha256'
        salt_bytes: number of bytes to for salt
        iterations: number of hashing iteration 

    Returns:
        True

    Raises:
        ConfigurationError: users is not defined properly in YAML file
        ScannerError: Failed to parse YAML file
        sqlite3.DatabaseError: unable to connect to database
    """
    if algo in ['text', 'txt']:
        pw_str = f'text:{password}'

    else:
        b_salt = secrets.token_bytes(salt_bytes)
        b_pass = password.encode()

        b64str_salt, b64str_hash = _hash_password(
            algo, b_pass, b_salt, iterations)
        pw_str = f'{algo}:{iterations}:{b64str_salt}:{b64str_hash}'

    if USERS_DB_MODE == 'YAML':
        data = _load_file()
        data['users'].update({username: pw_str})

        with open(USERS_DB_PATH, 'w') as f:
            yaml.dump(data, f)

    elif USERS_DB_MODE == 'SQLITE3':
        con, cur = _load_file()
        sql = """
            INSERT INTO users 
            VALUES(:username,:password) 
            ON CONFLICT(username) 
            DO UPDATE SET 
            password=:password
            WHERE 
            username=:username
        """

        cur.execute(sql,
                    {
                        "username": username,
                        "password": pw_str
                    })
        con.commit()

    return True


def _delete_user(username: str) -> bool:
    """
    Add or update a user in the database 

    Args:
        username: unique username of user

    Returns:
        True if successful else False

    Raises:
        ConfigurationError: users is not defined properly in YAML file
        ScannerError: Failed to parse YAML file
        sqlite3.DatabaseError: unable to connect to database
    """

    if USERS_DB_MODE == 'YAML':
        data = _load_file()
        pw = data['users'].pop(username, None)

        if pw == None:
            return False

        with open(USERS_DB_PATH, 'w') as f:
            yaml.dump(data, f)

    if USERS_DB_MODE == 'SQLITE3':
        con, cur = _load_file()
        sql = """
            DELETE FROM users
            WHERE
            username=:username;
        """

        cur.execute(sql, {
            "username": username
        }
        )
        con.commit()

    return True


def _hash_password(algo: str, password: bytes, salt: bytes, iterations: int):
    """
    Generate a password hash using pbkdf2_hmac

    Args:
        algo: hashing algorithm, defaults 'sha256'
        password: encoded password bytes
        salt: encoded salt bytes
        iterations: number of hashing iteration 

    Returns:
        True

    Raises:
        ValueError: When hashing algo is unknown or unsupported 
    """
    pw_hash = hashlib.pbkdf2_hmac(algo, password, salt, iterations)

    b64str_salt = str(base64.b64encode(salt), 'utf-8')
    b64str_hash = str(base64.b64encode(pw_hash), 'utf-8')

    return b64str_salt, b64str_hash


def verify_password(username: str, password: str) -> bool:
    """
    verify password of a user in the database

    Args:
        username: unique username of user
        password: password for user

    Returns:
        True if successful else False
    """
    try:
        logger.debug(f"Verifying password for '{username}' locally")
        saved_pw_str = _get_password(username)

        if saved_pw_str == None:
            logger.warning(f"Failed! - no such user")
            return False

        success = False
        algo, data = saved_pw_str.split(":", 1)
        algo = algo.lower()

        if algo in ["text", "txt"]:
            success = data == password

        else:  # sha256:iterations:salt:sha256(salt+password)
            data = data.split(":")

            iterations = int(data[0])
            b64str_salt = data[1] if len(data) == 3 else ''
            b64str_saved_hash = data[2] if len(data) == 3 else data[1]

            b64str_salt, b64str_hash = _hash_password(
                algo,
                password.encode(),
                base64.b64decode(b64str_salt),
                iterations
            )

            success = b64str_saved_hash == b64str_hash

        if success:
            logger.debug(f"Success!")
            return True
        else:
            logger.warning(f"Failed - wrong password")
            return False

    except Exception as e:
        logger.critical(
            f"Failed - unable to process password: {e}")

        return False


def add_user(*args, **kwargs):
    """
    Add a user in the database 

    Args:
        *args:
            username: unique username of user
            password: password for user

        **kwargs:
            algo: hashing algorithm, defaults 'sha256'
            salt_bytes: number of bytes to for salt
            iterations: number of hashing iteration 

    Returns:
        status:bool, message:str
    """

    if _get_password(args[0]) != None:
        logger.warning(f"Failed: user '{args[0]}' exist")
        return False, f"Failed: user '{args[0]}' exist"
    else:
        _update_users(*args, **kwargs)
        logger.info(f"Success: user '{args[0]}' added!")
        return True, f"Success: user '{args[0]}' added!"


def edit_user(username: str, new_password: str, old_password: str = None, verify: bool = False, **kwargs):
    """
    Edit a user in the database 

    Args:
        username: unique username of user
        new_password: password for user

        old_password: current password of user. only needed if verify=True
        verify: check for current password 

        **kwargs:
            algo: hashing algorithm, defaults 'sha256'
            salt_bytes: number of bytes to for salt
            iterations: number of hashing iteration 

    Returns:
        status:bool, message:str

    """

    status = False
    msg = ''
    try:

        if verify == True and old_password == None:
            msg = "Failed: when verify=True, old password must be given"

        elif verify == True and verify_password(username, old_password) == False:
            msg = "Failed: verify=True, password mismatch"

        elif _get_password(username) == None:
            msg = f"Failed: user '{username}' not found"

        else:
            status = _update_users(username, new_password)
            msg = f"Success: user password '{username}' updated"

        if status:
            logger.info(msg)
        else:
            logger.warning(msg)

        return status, msg

    except Exception as e:
        logger.critical(e)
        return False, str(e)


def delete_user(username: str, old_password: str = None, verify: bool = False):
    """
    Delete a user in the database 

    Args:
        username: unique username of user

        old_password: current password of user. only needed if verify=True
        verify: check for current password 

    Returns:
        status:bool, message:str
    """
    status = False
    msg = ''
    try:

        if verify == True and old_password == None:
            msg = "Failed: when verify=True, old password must be given"

        elif verify == True and verify_password(username, old_password) == False:
            msg = "Failed: verify=True, password mismatch"

        else:
            status = _delete_user(username)
            msg = f"Success: user '{username}' deleted" if status else f"Failed: user '{username}' not found"

        if status:
            logger.info(msg)
        else:
            logger.warning(msg)

        return status, msg

    except Exception as e:
        logger.critical(e)
        return False, str(e)
