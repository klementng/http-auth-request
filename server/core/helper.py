import base64
import copy
import logging

import cachetools.func
import flask
import flask.sessions
import ruamel.yaml

from server.auth.exception import AuthenticationConfigError
from server.auth.modules import AuthenticationModule

logger = logging.getLogger(__name__)


def parse_config(path: str):
    try:
        logger.debug("Parsing YAML config file")

        yaml_f = open(path)
        config = ruamel.yaml.safe_load(yaml_f)
        yaml_f.close()

        settings = config["settings"]
        modules = config["modules"]

        for key in modules.keys():
            modules[key] = AuthenticationModule.from_dict(modules[key])  # type: ignore

        return settings, modules

    except Exception as e:
        logger.fatal(f"Aborting. Invalid Configuration: {e} ")
        raise AuthenticationConfigError(e)


def update_login_session(username: str, request: flask.Request, session: flask.sessions.SessionMixin):
    ses = session.get('auth')
    authorized_path = request.path

    if ses != None and ses['username'] == username:
        ses['authorized_path'].append(authorized_path)

        session["auth"] = {
            'username': username,
            'authorized_path': ses['authorized_path']
        }

    else:
        session["auth"] = {
            'username': username,
            'authorized_path': [authorized_path]
        }

    session.modified = True


def process_session(module: AuthenticationModule, request: flask.Request, session: flask.sessions.SessionMixin) -> flask.Response:

    @cachetools.func.ttl_cache(ttl=3)
    def _func(path, session_id):

        ses = session.get('auth')

        if ses == None:
            flask.abort(401)

        if path in ses['authorized_path']:
            return flask.Response(f"", 200)

        else:
            if module.local != None:
                user = module.local.db.get_user(ses['username'])

                if user != None and user.verify_role(module.local.allowed_roles):
                    update_login_session(ses['username'], request, session)
                    return flask.Response(f"", 200)

    return _func(request.path, session.sid)  # type: ignore


def process_auth_header(module: AuthenticationModule, request: flask.Request, session: flask.sessions.SessionMixin):
    """Processes incoming 'Authorization' header

    Args:
        auth_header: base64 encoded string
        modules: authentication module

    Returns:
        Response
    """

    if request.authorization == None:
        return flask.abort(401)

    if request.authorization.type != 'basic':
        return flask.abort(401, f"authentication '{request.authorization.type}' is not supported")

    username = request.authorization.parameters.get('username')
    password = request.authorization.parameters.get('password')

    return process_login(module, request, session, username, password)


def process_post_request(module: AuthenticationModule, request: flask.Request, session: flask.sessions.SessionMixin):
    """Processes incoming 'Authorization' header

    Args:
        modules: authentication module

    Returns:
        Response
    """

    username = request.form.get('username')
    password = request.form.get('password')
    remember = request.form.get('remember')

    res = process_login(module, request, session, username, password)

    if res.status_code == 200 and remember != None:
        session.permanent = True
        session.modified = True

    return res


def process_login(module: AuthenticationModule, request: flask.Request, session: flask.sessions.SessionMixin, username: str | None, password: str | None):

    if username == None or password == None:
        return flask.abort(401)
    else:
        username = username.strip()

    status_code = module.login(
        username,
        password,
        request_headers=copy.copy(dict(request.headers))
    )

    if status_code == 200:
        update_login_session(username, request, session)
        return flask.Response(f"successfully authenticated as {username}", 200)

    elif status_code == 403:
        return flask.abort(403, f"{username} is not authorized for this area")

    elif status_code == 401:
        return flask.abort(401, f"invalid username / password")

    else:
        return flask.abort(500, f"something went wrong")
