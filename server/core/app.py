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
from flask_session import Session
import werkzeug.exceptions

import server.auth.modules
from server.core.helper import parse_config
import server.config as config

app_settings, auth_modules = parse_config(config.CONFIG_PATH)

logger = logging.getLogger(__name__)
app = Flask(__name__)

for k in os.environ.keys(): 
    if k.startswith("FLASK_"):
        if os.environ[k].lower() in ['true' ,'false']:
            app.config[k.replace("FLASK_", "")] = os.environ[k].lower() == 'true'
        else:
            app.config[k.replace("FLASK_", "")] = os.environ[k]

app_sess = Session(app)
app_csrf = CSRFProtect(app)


def start(debug_mode: bool = False) -> None:
    """Start the server using waitress

    Args:
        debug_mode: start werkzeug with debug on

    Returns:
        None
    """
    logger.info("Server started!")

    if debug_mode == True:
        app.run(
            app_settings["server"]["host"],
            app_settings["server"]["port"], 
            debug=True
        )
    else:
        waitress.serve(
            app,
            host=app_settings["server"]["host"],
            port=app_settings["server"]["port"]
        )


@app.route("/", defaults={"path": "/auth"}, methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
@app.route("/<path:path>", methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
def main(path):
    """Main flask application"""

    path = request.path if request.path != '/' else "/auth"
    request.path = path

    if 'logout' in request.args:
        session.clear()

        if request.headers.get("Authorization") == None:
            return Response("Logout successful <br> <a href=/>Home</a>", 401)
        
        elif request.headers.get("Authorization") == "Basic Og==":
            return Response("Logout successful <br> <a href=/>Home</a>", 401)

        return abort(401)

    res = process_session(path)
    if res != None:
        return res

    auth_header = request.headers.get("Authorization")

    if auth_header != None:
        return process_auth_header(
            path,
            auth_header
        )

    else:
        return abort(401)

def process_session(path):
    
    try:
        ses = session.get('auth')
        # Check if user is already login to the request path from session
        if ses != None and path != None:
            if path in ses['authorized_path']:
                return Response(f"", 200)
                
            else:
                try:
                    mod:server.auth.modules.AuthenticationModule = auth_modules[path]
                except KeyError:
                    return abort(404, f"{path} is not defined")
            
            
            #  Check if login cred is valid for new request path 
            if mod.local != None:
                user=mod.local.db.get_user(ses['username'])
                
                if user != None and user.verify_role(mod.local.allowed_roles):
                    update_user_login_session(ses['username'], path)
                    return Response(f"", 200)
    except:
        pass


def update_user_login_session(username, authorized_path: str):    
    ses = session.get('auth')

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


def process_auth_header(path: str, auth_header: str):
    """Processes incoming 'Authorization' header

    Args:
        auth_header: base64 encoded string
        modules: authentication module

    Returns:
        Response
    """

    logger.debug("Processing 'Authorization' header")

    try:
        method, data = auth_header.split(" ")
        username, password = str(base64.b64decode(data), 'utf-8').split(":", 1)
        mod:server.auth.modules.AuthenticationModule = auth_modules[path]

        if method != "Basic":
            return abort(401, f"authentication '{method}' is not supported")

    except KeyError:
        return abort(404, f"{path} is not defined")

    except:
        return abort(401, f"A malformed 'Authorization' header received")

    status_code = mod.login(
        username,
        password,
        request_headers=copy.copy(dict(request.headers))
    )

    if status_code == 200:
        update_user_login_session(username, path)
        return Response(f"successfully authenticated as {username}", 200)

    elif status_code == 403:
        return abort(403, f"{username} is not authorized for this area")

    elif status_code == 401:
        return abort(401, f"invalid username / password")

    else:
        return abort(500, f"something went wrong")


@app.errorhandler(401)
def unauthorized(e: werkzeug.exceptions.Unauthorized) -> Response:
    """
    Send a request for authentication
    """
    
    m = auth_modules.get(request.path)

    if m != None:
        return Response(str(e), 401, {'WWW-Authenticate': f'{m.method} realm="{m.realm}"'})

    else:
        logger.warning(f"{request.path} is not defined. Check your nginx config!!!")
        return Response(str(e), 401, {'WWW-Authenticate': f'Basic'})

@app.errorhandler(403)
def forbidden(e) -> Response:
    """
    Send a forbidden response. This occurs when user is logged in but not authorized
    """
    return Response(str(e), 403)


@app.errorhandler(404)
def not_found(e) -> Response:
    """
    Send a not found response. This occurs for misconfiguration in nginx 
    """

    return Response(str(e), 404)


@app.errorhandler(502)
def gateway_error(e) -> Response:
    """
    Send a not found response. This occurs for misconfiguration in nginx 
    """

    return Response(str(e), 502)
