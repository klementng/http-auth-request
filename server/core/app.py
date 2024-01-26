"""HTTP authentication server.

A Flask application that provide basic access control using basic HTTP authentication method.  

Typical usage example:
    import server.core
    server.core.start(SETTINGS_PATH, debug_mode=False)
"""

import base64
import copy
import logging
import os

import cachetools
import cachetools.func
import waitress
import werkzeug.exceptions
from flask import Flask, Response, abort, request, session, render_template
from flask_wtf.csrf import CSRFProtect

import server.auth.modules
import server.config as config
from flask_session import Session
from server.core.helper import *

app_config, auth_modules = parse_config(config.CONFIG_PATH)

logger = logging.getLogger(__name__)
app = Flask(__name__,template_folder=config.TEMPLATE_FOLDER)

for k in os.environ.keys():
    if k.startswith("FLASK_"):

        try:
            app.config[k.replace("FLASK_", "")] = int(os.environ[k])
        except ValueError:
            if os.environ[k].lower() in ['true', 'false']:
                app.config[k.replace("FLASK_", "")
                           ] = os.environ[k].lower() == 'true'
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
            app_config["server"]["host"],
            app_config["server"]["port"],
            debug=True
        )
    else:
        waitress.serve(
            app,
            host=app_config["server"]["host"],
            port=app_config["server"]["port"],
            threads=app_config["server"]["threads"]
        )


@app.route("/", defaults={"path": "/auth"}, methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
@app.route("/<path:path>", methods=['POST', 'GET', "HEAD", "PUT", "DELETE"])
def main(path):
    """Main flask application"""

    path = request.path if request.path != '/' else "/auth"
    request.path = path
    redirect_url = request.args.get("redirect_url", "/")

    try:
        module = auth_modules[request.path]
    except KeyError:
        return abort(404)
    
    if 'logout' in request.args:
        logger.debug('Logging out')

        for key in list(session.keys()):
            session.pop(key)
        
        session.modified = True
        session.clear()

        a_h = request.headers.get("Authorization")

        if a_h == None or a_h == "Basic Og==":
            return Response(f"Logout successful <br> <a href={redirect_url}>Home</a>", 401)

        else:
            return abort(401)
    
    elif session.get('auth') != None:
        res = process_session(module, request, session)

    elif request.method == 'POST':
        res = process_post_request(module, request, session)

    elif request.authorization != None:
        res = process_auth_header(module, request, session)
    
    else:
        if 'login' in request.args:
            return render_template("index.html"), 401
        
        else:
            return abort(401)
    
    if res.status_code == 200:

        if 'remember' in request.args:
            session.permanent = True
            session.modified = True

        if redirect_url != None:
            res.set_data(
                str(res.data, 'utf-8') +
                f"""
                <p>You will be redirected in 1 seconds to <a href={redirect_url}> {redirect_url}</a> </p>\
                <script>
                    var timer = setTimeout(
                        function() {{window.location='{redirect_url}'}}, 1000);
                </script>
                """
            )

    return res


@app.errorhandler(401)
def unauthorized(e: werkzeug.exceptions.Unauthorized) -> Response:
    """
    Send a request for authentication
    """

    m = auth_modules.get(request.path)

    if 'login' in request.args:
        flask.flash("Incorrect username or password",'danger')
        return Response(
            render_template("index.html"),
            401
        )

    elif m != None:
        return Response(
            str(e),
            401,
            {'WWW-Authenticate': f'{m.method} realm="{m.realm}"'}
        )
    
    else:
        return abort(404, f"{request.path} is not defined. Check your nginx config!!!")


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
