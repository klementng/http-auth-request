"""HTTP authentication server.

A Flask application that provide basic access control using basic HTTP authentication method.  

Typical usage example:
    import server.core
    server.core.start(SETTINGS_PATH, debug_mode=False)
"""

import base64
import logging
import os
import ruamel.yaml
import shutil
import waitress
import cachetools.func

from flask import Flask, Response, request, abort

from server.authentication import AuthenticationModule
from server.shared import ConfigurationError

CONFIG_DIR = os.getenv("CONFIG_DIR")
SETTINGS_PATH = os.getenv("SETTINGS_PATH")
CACHE_TTL = float(os.getenv("CACHE_TTL","60"))

if SETTINGS_PATH == None:
    raise EnvironmentError("SETTINGS_PATH must be set")

MODULES = None
SETTINGS = None
SETTINGS_MTIME = os.stat(SETTINGS_PATH).st_mtime

logger = logging.getLogger(__name__)
app = Flask(__name__)


if not os.path.exists(SETTINGS_PATH):

    logger.critical(
        f"Config file not found, creating config file at {SETTINGS_PATH}...")
    logger.critical(
        "Please edit the config file and restart the server !!!")

    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    shutil.copy("examples/default.yml", SETTINGS_PATH)
    os.chmod(SETTINGS_PATH, 600)


def parse_config():
    try:
        logger.debug("Opening config file")
        yaml_f = open(SETTINGS_PATH)
        logger.debug("Parsing YAML config file")
        config = ruamel.yaml.safe_load(yaml_f)
        yaml_f.close()

        settings = config["settings"]
        modules = config["modules"]

        for key in modules.keys():
            modules[key] = AuthenticationModule.from_dict(modules[key])

        return settings,modules

    except Exception as e:
        logger.fatal(f"Aborting. Invalid Configuration: {e} ")
        raise


SETTINGS,MODULES = parse_config()

def start(debug_mode: bool = False) -> None:
    """Start the server using waitress

    Args:
        debug_mode: start werkzeug with debug on

    Returns:
        None

    Raises:
        SystemExit: failed to parse config file 
    """
    global MODULES
    global SETTINGS

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


@app.route("/", defaults={"path": "default"}, methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
@app.route("/<path:catch_all>", methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
def main(catch_all):
    """Main flask application"""

    global SETTINGS_MTIME
    global MODULES    
    global SETTINGS

    if SETTINGS_MTIME != os.stat(SETTINGS_PATH).st_mtime:
        logger.info("Changes to settings detected! reloading authentication modules")
        
        try:
            SETTINGS,MODULES = parse_config()
            SETTINGS_MTIME = os.stat(SETTINGS_PATH).st_mtime

        except:
            logger.critical("Unable to reload authentication modules!. Check your config!")

    logger.debug(catch_all)
    logger.debug(request.path)
    logger.debug(request.args.get('allowed_users', None))
    logger.debug(request.args.get('denied_users', None))

    module = request.path
    if  module not in MODULES:
        return abort(404)

    auth_header = request.headers.get("Authorization", None)
    allowed_users = request.args.get('allowed_users', None)
    denied_users = request.args.get('denied_users', None)

    if auth_header == None:
        logger.debug("No 'Authorization' header sent. Returning 401")
        return abort(401)

    if allowed_users != None:
        allowed_users = tuple(allowed_users.split(","))
    
    if denied_users != None:
        denied_users = tuple(denied_users.split(","))

    return process_auth_header(auth_header, module, allowed_users, denied_users)


# caching to reduce server load due to burst requests
@cachetools.func.ttl_cache(ttl=CACHE_TTL)
def process_auth_header(auth_header: str, module: str, allowed_users: tuple = None, denied_users: tuple = None) -> Response:
    """Processes incoming 'Authorization' header

    Args:
        auth_header: base64 encoded string

    Returns:
        Response(msg, 200)

    Raises:
        abort() with 401, 403 or 404 status code
    """

    logger.debug("Processing 'Authorization' header")

    try:
        method, data = auth_header.split(" ")
        username, password = str(base64.b64decode(data), 'utf-8').split(":", 1)
        mod = MODULES[module]

    except KeyError:
        logger.warn(
            f"{request.path} is not defined. Check your configs!!!, Returning 404")
        return abort(404)

    except:
        logger.warn(
            f"A malformed 'Authorization' header received, Returning 401")
        return abort(401)

    if allowed_users != None and username not in allowed_users:
        logger.warn(
            f"User: {username} not in accepted users args: {allowed_users}")        
        return abort(403)
    
    if denied_users != None and username in denied_users:
        logger.warn(
            f"User: {username} is denied due to denied_users args: {denied_users}")        
        return abort(403)


    if method == "Basic":
        status_code = mod.login(username, password, request_headers=request.headers)

        if status_code == 200:
            return Response("Success", 200)

        elif status_code == 403:
            return abort(403, f"Forbidden. {username} is not authorized for this area")

        else:
            return abort(401)

    else:
        logger.warn(f"http authentication '{method}' is not supported. Returning 401")
        return abort(401)


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
        logger.warn(
            f"{request.path} is not defined. Check your configs!!!, using default")
        return Response(msg, 401, {'WWW-Authenticate': f'Basic'})


@app.errorhandler(403)
def forbidden(e, msg="Forbidden <a>") -> Response:
    """
    Send a forrbbien response. This occurs when user is logged in but not authorized

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
