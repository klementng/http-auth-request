"""
Module containing classes that handle authentication.
"""

import json
import requests
import logging

from dataclasses_json import dataclass_json, Undefined, CatchAll
from dataclasses import dataclass, KW_ONLY


import server.users
from server.shared import ConfigurationError

logger = logging.getLogger(__name__)

from flask import request as flask_request

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
    forward_headers: bool = False

    data: str | None = None
    json: dict | None = None
    headers: dict | None = None

    kwargs: CatchAll = None

    def __post_init__(self):
        self.method = self.method.upper()

        if self.forward_headers == True:
            self.headers.update(flask_request.headers)

    def login(self, username, password):
        logger.debug(f"{username} is logging in upstream at {self.url}")

        kw = self.to_json().replace(
            "<<username>>", username
        ).replace(
            "<<password>>", password
        )

        kw = json.loads(kw)
        kw.pop('forward_headers')

        if "kwargs" in kw:
            kw.update(kw.pop("kwargs"))

        re = requests.request(**kw)

        if re.status_code == 200:
            logger.info(f"{username} upstream login successful!")
            return 200
        else:
            logger.warning(
                f"{username} upstream login failed with code: {re.status_code}, returning 401")
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
    """
    mode: str

    method: str = 'Basic'
    realm: str = ''

    _: KW_ONLY
    upstream: AuthenticationUpstream | None = None
    users: list[str] | None = None

    def __post_init__(self):
        self.method = self.method.title()
        self.mode = self.mode.lower()

        if self.method not in ["Basic"]:
            logger.fatal(
                f"module: 'method' {self.method} is not supported. Check your configuration!!!")

            raise ConfigurationError(
                f"module: 'method' {self.method} is not supported. Check your configuration!!!")

        if self.mode not in ["local", "upstream",'dynamic']:
            logger.fatal(
                f"module: 'mode' {self.mode} can be either ['local', 'upstream','dynamic'] only. Check your configuration!!!")

            raise ConfigurationError(
                f"module: 'mode' {self.mode} can be either ['local', 'upstream','dynamic'] only. Check your configuration!!!")

        if self.mode in ["upstream",'dynamic'] and self.upstream == None:
            logger.fatal(
                f"module: 'upstream:' key must be configured when using {self.mode} mode")

            raise ConfigurationError(
                f"module: 'upstream:' key must be configured when using {self.mode} mode")

        if self.users == []:
            self.users = None

    def is_user_part_of_group(self, username):
        """Check if user is part of the current group

        Args:
            username:
                username who is logging in

        Returns:
            True if in current group else False
        """

        if self.users == None:
            return True
        else:
            return username in self.users

    def login(self, username, password):
        """Login to server

        Processes the login request using username and password locally or 
        passes it to the upstream server.

        Args:
            username:
                user who is logging in
            password:
                password of user who is logging in

        Returns:
            True if successfully, else return false
        """

        logger.info(f"'{username}' is logging in")

        success = False

        if self.mode == "upstream":
            status_code = self.upstream.login(username, password)
            success = True if status_code == 200 else False

        elif self.mode == "local":
            success = server.users.verify_password(username, password)

        elif self.mode == "dynamic":
            status_code = self.upstream.login(username, password)
            success = True if status_code == 200 else server.users.verify_password(username, password)

        if success and self.is_user_part_of_group(username):
            logger.info(f"'{username}' login successful - returning 200")
            return 200

        elif success:
            logger.warning(
                f"'{username}' login successful - but unauthorized for area - returning 403")
            return 403

        else:
            logger.warning(
                f"'{username}' login failed - returning 401")
            return 401
