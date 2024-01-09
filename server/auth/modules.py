"""
Module containing classes that handle authentication.
"""

import json
import requests
import logging

from typing import Optional

from dataclasses_json import dataclass_json, Undefined, CatchAll
from dataclasses import dataclass, KW_ONLY

from server.auth.exception import AuthenticationConfigError
from server.users.database import UserDatabase


@dataclass_json(undefined=Undefined.INCLUDE)
@dataclass
class AuthenticationUpstream:
    """Allow login to an upstream server

    This class uses requests modules to send a HTTP(s)
    request to an upstream server.

    Attributes:
        url: upstream url
        method: HTTP method
        allow_redirects: allow to be redirected
        data: data to be sent
        json: json data to be sent
        headers: headers to be sent

        **kwargs: additional kwargs passed to requests.request(**kwargs)
    """
    url: str
    method: str = "POST"
    allow_redirects: bool = False

    data: Optional[str] = None
    json: Optional[dict] = None
    headers: Optional[dict] = None
    kwargs: CatchAll = None

    def __post_init__(self):
        self.method = self.method.upper()
        self.log = logging.getLogger('AuthenticationUpstream')

    def login(self, username: str, password: str, flask_headers: Optional[dict] = None) -> int:
        """
        The `login` function sends a request to an upstream login server with a username and password, and
        returns the HTTP status code of the response.
        
        Args:
          username (str): The username of the user who is signing in.
          password (str): The `password` parameter is a string that represents the user-entered password for
        logging in.
          flask_headers (Optional[dict]): The `request_headers` parameter is an optional dictionary that
        contains the headers from flask. It forwards headers in the list defined in headers['__forward'] of the configuration
        
        Returns:
          an integer representing the HTTP status code. If the login is successful, it returns 200.
        Otherwise, it returns the status code received from the upstream server. If an exception occurs
        during the request, it returns 502.
        """

        self.log.debug(f"{username} is logging in upstream at {self.url}")

        kw = json.loads(
            self.to_json().replace(  # type: ignore
                "<<username>>", username
            ).replace(
                "<<password>>", password
            )
        )

        if kw["headers"] != None:
            forward_list = kw["headers"].pop("__forward", [])

            if flask_headers != None:
                for k in forward_list:
                    if k in flask_headers:
                        self.log.debug(
                            f"Forwarding '{k}' header to upstream server")
                        kw['headers'].update(
                            {k: flask_headers[k]})  # type: ignore

        if "kwargs" in kw:
            kw.update(kw.pop("kwargs"))

        try:
            re = requests.request(**kw)

            if re.status_code == 200:
                self.log.info(f"{username} upstream login successful!")
                return 200
            else:
                self.log.warning(
                    f"{username} upstream login failed with code: {re.status_code}")
                return re.status_code
        except:
            return 502


@dataclass_json
@dataclass
class AuthenticationLocal:
    """Allow login using a local yaml file

    Attributes:
        db_path: path to a yaml file with the key 'users' defined
    """

    db_path: str
    allowed_roles: list[str] = None  # type: ignore

    def __post_init__(self):
        self.db = UserDatabase(self.db_path)
        self.log = logging.getLogger('AuthenticationLocal')

        if self.allowed_roles == None:
            self.log.warning("Allowed Roles is empty")
            self.allowed_roles = []

    def login(self, username: str, password: str) -> int:
        """
        The `login` function takes a username and password as input, checks if the user exists in the
        database, verifies the password, and returns an appropriate status code based on the outcome.
        
        Args:
          username (str): The username parameter is a string that represents the username of the user
        trying to log in.
          password (str): The password parameter is a string that represents the user's password.
        
        Returns:
          an integer value. The possible return values are:
            - 200: success
            - 401: wrong username/password
            - 403: forbidden area 
        """
        self.log.info(f"'{username}' is logging in locally")

        user = self.db.get_user(username)

        if user == None:
            self.log.warning(f"'{user}' not found")
            return 401

        if user.verify_password(password) == True:

            if any(True for x in user.roles if x in self.allowed_roles):
                self.log.info(f"'{username}' login successful")
                return 200
            else:
                self.log.warning(f"'{username}' is not allowed in this area")
                return 403

        return 401


@dataclass_json
@dataclass
class AuthenticationModule:
    """Core Authentication module that handle all login requests.

    Attributes:
        mode: HTTP Authentication mode
        method: local or upstream server

        realm: HTTP Authentication realm
        upstream (optional): AuthenticationUpstream if method == upstream
        users (optional): list of user part the current module

    Raises: 
        AuthenticationConfigError: Occurs when that misconfiguration with authentication modules
    """

    mode: str

    method: str = 'Basic'
    realm: str = ''

    _: KW_ONLY

    local: Optional[AuthenticationLocal] = None 
    upstream: Optional[AuthenticationUpstream] = None

    def __post_init__(self):
        self.method = self.method.title()
        self.mode = self.mode.lower()
        self.log = logging.getLogger("AuthenticationModule")

        try:
            if self.method not in ["Basic"]:
                raise AuthenticationConfigError(
                    f"module: 'method' {self.method} is not supported. Check your configuration!!!")

            if self.mode == 'local':

                if isinstance(self.local, dict):
                    self.local = AuthenticationLocal(**self.local)
                elif isinstance(self.local, AuthenticationLocal):
                    pass
                else:
                    raise AuthenticationConfigError(
                        "local key must be defined")

            elif self.mode == 'upstream':

                if isinstance(self.upstream, dict):
                    self.upstream = AuthenticationUpstream(**self.upstream)
                elif isinstance(self.upstream, AuthenticationUpstream):
                    pass
                else:
                    raise AuthenticationConfigError(
                        "upstream key must be defined")

            elif self.mode == 'dynamic':
                if isinstance(self.local, dict):
                    self.local = AuthenticationLocal(**self.local)
                elif isinstance(self.local, AuthenticationLocal):
                    pass
                else:
                    raise AuthenticationConfigError(
                        "local key must be defined")

                if isinstance(self.upstream, dict):
                    self.upstream = AuthenticationUpstream(**self.upstream)
                elif isinstance(self.upstream, AuthenticationUpstream):
                    pass
                else:
                    raise AuthenticationConfigError(
                        "upstream key must be defined")

            else:
                raise AuthenticationConfigError(
                    f"module: 'method' {self.method} is not supported. Check your configuration!!!")

        except AuthenticationConfigError as e:
            self.log.fatal(e)
            raise e

    def login(self, username: str, password: str, request_headers: Optional[dict] = None):
        """Login to server

        Processes the login request using username and password locally or 
        passes it to the upstream server.

        Args:
            username (str): user who is logging in
            password (str): password of user who is logging in

        Returns:
            int: HTTP status code. 200 if successful
        """

        self.log.info(f"'{username}' is logging in")

        if self.mode == "local":
            return self.local.login(username, password)

        elif self.mode == "upstream":
            return self.upstream.login(username, password, request_headers)

        elif self.mode == "dynamic":
            if self.upstream.login(username, password, request_headers) == 200:
                return 200
            else:
                return self.local.login(username, password)
