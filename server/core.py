"""HTTP authentication server.

A Flask application that provide basic access control using basic HTTP authentication method.  

Typical usage example:
    import server.core
    server.core.start(SETTINGS_PATH, debug_mode=False)
"""

import base64
import logging
import os
import copy
import waitress
import cachetools
import cachetools.func

from flask import Flask, request, Response, request, abort, session
from flask_wtf.csrf import CSRFProtect

from frozendict import frozendict

from server.helper import parse_config
from server.shared.func import freezeargs

CONFIG_DIR = os.environ["CONFIG_DIR"]
SETTINGS_PATH = os.environ["SETTINGS_PATH"]
CACHE_TTL = float(os.environ["CACHE_TTL"])

SETTINGS, MODULES = parse_config(SETTINGS_PATH)
SETTINGS_MTIME = os.stat(SETTINGS_PATH).st_mtime

logger = logging.getLogger(__name__)
app = Flask(__name__)
csrf = CSRFProtect(app)

for k in os.environ.keys():
    if k.startswith("FLASK_"):
        app.config[k.replace("FLASK_", "")] = os.environ[k]

def start(debug_mode: bool = False) -> None:
    """Start the server using waitress

    Args:
        debug_mode: start werkzeug with debug on

    Returns:
        None

    Raises:
        SystemExit: failed to parse config file 
    """
    logger.info("Server started!")

    if debug_mode == True:
        app.run(SETTINGS["server"]["host"],
                SETTINGS["server"]["port"], debug=True)
    else:
        waitress.serve(
            app,
            host=SETTINGS["server"]["host"],
            port=SETTINGS["server"]["port"]
        )


@app.route("/", defaults={"path": "/auth"}, methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
@app.route("/<path:path>", methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
def main(path):
    """Main flask application"""

    module = request.path if request.path != '/' else "/auth"
    request.path = module

    session_group = session.get("group","").split(":")

    if module in session_group:
        return Response('',200)

    auth_header = request.headers.get("Authorization")
    
    login_status,msg = process_auth_header(auth_header,module,request.args) #type: ignore
    
    if login_status == 200:
        session["group"] = ":".join(session_group + [module])
        session.modified=True
        return Response(msg,200)
    else:
        abort(login_status,msg)

@freezeargs
@cachetools.func.ttl_cache(ttl=CACHE_TTL)
def process_auth_header(auth_header: str, module: str, args: frozendict) -> tuple[int, str]:
    """Processes incoming 'Authorization' header

    Args:
        auth_header: base64 encoded string

    Returns:
        status_code, msg
    """

    logger.debug("Processing 'Authorization' header")

    try:
        method, data = auth_header.split(" ")
        username, password = str(base64.b64decode(data), 'utf-8').split(":", 1)
        mod = MODULES[module]

    except KeyError:
        return 404, f"{request.path} is not defined"

    except:
        return 401, f"A malformed 'Authorization' header received"

    allowed_users = args.get('allowed_users')
    denied_users = args.get('denied_users')

    if allowed_users != None:
        allowed_users = allowed_users.split(",")

        if username not in allowed_users:
            return 403, f"{username} is not allowed in this area"

    if denied_users != None:
        denied_users = denied_users.split(",")

        if username in denied_users:
            return 403, f"{username} is not allowed in this area"

    if method == "Basic":
        status_code = mod.login(
            username,
            password,
            request_headers=copy.copy(dict(request.headers))
        )

        if status_code == 200:
            return 200, f"successfully authenticated as {username}"
        elif status_code == 403:
            return 403, f"{username} is not authorized for this area"
        elif status_code == 401:
            return 401, f"invalid username / password"
        else:
            return 500, f"something went wrong"

    else:
        return 401, f"authentication '{method}' is not supported"


@app.errorhandler(401)
def unauthorized(e: int, msg="Unauthorized") -> Response:
    """
    Send a request for authentication

    Args:
        e: status code
        msg: error message

    Returns:
        Response(msg, 401)
    """
    m = MODULES.get(request.path)

    if m != None:
        return Response(msg, 401, {'WWW-Authenticate': f'{m.method} realm="{m.realm}"'})

    else:
        logger.warning(
            f"{request.path} is not defined. Check your configs!!!, using default /auth")
        return Response(msg, 401, {'WWW-Authenticate': f'Basic'})


@app.errorhandler(403)
def forbidden(e, msg="Forbidden <a>") -> Response:
    """
    Send a forbidden response. This occurs when user is logged in but not authorized

    Args:
        e: status code
        msg: error message

    Returns:
        Response(msg, 403)
    """
    return Response(msg, 403)


@app.errorhandler(404)
def not_found(e, msg="Not Found") -> Response:
    """
    Send a not found response. This occurs for misconfiguration in nginx 

    Args:
        e: status code
        msg: error message

    Returns:
        Response(msg, 404)
    """

    return Response(msg, 404)


@app.errorhandler(502)
def akkk(e, msg="Upstream authentication error") -> Response:
    """
    Send a not found response. This occurs for misconfiguration in nginx 

    Args:
        e: status code
        msg: error message

    Returns:
        Response(msg, 404)
    """

    return Response(msg, 404)
