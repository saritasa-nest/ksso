import logging
import os
import sys

import flask.cli
import jwt
import requests
from flask import Flask, redirect, request

from ksso.exceptions import KCError


# Use Nuitka/PyInstaller temp directory if bundled
# If the script is running as a bundled executable (created by PyInstaller),
# 'sys.frozen' is set to True, and 'sys._MEIPASS' provides the path to the
# temporary directory where PyInstaller extracts bundled resources.
# Otherwise, use the current working directory as the base path.
def get_base_path():
    if hasattr(sys, "_MEIPASS"):
        # PyInstaller-like temp folder (if used)
        return sys._MEIPASS
    elif getattr(sys, "frozen", False):  # Nuitka or PyInstaller binary
        # Nuitka-compiled binary path
        return os.path.dirname(sys.executable)
    elif hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix:
        # Inside a venv
        return os.path.dirname(os.path.abspath(__file__))
    else:
        # Default to the script's directory
        return os.path.dirname(os.path.abspath(__file__))


base_path = get_base_path()

app = Flask(__name__)
logger = logging.getLogger("error")

# Suppress Flask logs as we want to output JSON text in the console
# that is later on will be parsed by aws-vault via credentials process output
# so we don't need anything but the desired output
if not os.environ.get("DEBUG"):
    app.logger.disabled = True
    flask.cli.show_server_banner = lambda *args: None
    log = logging.getLogger("werkzeug")
    log.disabled = True


@app.route("/")
def login():
    """Redirect user to Keycloak for authentication.

    Constructs the authentication URL using Keycloak's authorization endpoint
    and redirects the user to initiate the login process.

    Key Components:
        - 'client_id': Identifies the Keycloak client.
        - 'response_type': Specifies that the response will contain an
                           authorization code.
        - 'redirect_uri': Callback URL to receive the authorization code
                          (which is callback function below).

    Returns:
        HTTP 302 Redirect: Redirects the user's browser to the Keycloak
        login page.
    """
    auth_url = (
        f"{app.config['KEYCLOAK_URL']}/auth?"
        f"client_id={app.config['CLIENT_ID']}"
        f"&response_type=code"
        f"&redirect_uri={app.config['REDIRECT_URI']}"
    )
    return redirect(auth_url)


@app.route("/callback")
def callback():
    """Handle the redirect from Keycloak and exchange the authorization code
       for an access token.

    Steps:
        1. Retrieve the 'code' parameter from the query string,
           provided by Keycloak.
        2. Send a POST request to Keycloak's token endpoint to exchange the
           code for an access token.
        3. Decode the token (without verification) to extract user session
           information.
        4. Pass the access token and session name back to the main application
           thread for further processing.
        5. Return a success message to the user's browser.

    Returns:
        str: HTML content to indicate successful authentication.
    """
    code = request.args.get("code")

    # Exchange code for token
    token_url = f"{app.config['KEYCLOAK_URL']}/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": app.config["CLIENT_ID"],
        "redirect_uri": app.config["REDIRECT_URI"],
        "code": code,
    }

    response = requests.post(token_url, data=data, timeout=5)
    response.raise_for_status()
    token_response = response.json()
    access_token = token_response["access_token"]

    # Decode the token to extract the session name
    # (e.g., preferred_username or sub)
    decoded_token = jwt.decode(access_token, options={"verify_signature": False})
    session_name = (
        decoded_token.get("preferred_username")
        or decoded_token.get("email")
        or decoded_token.get("sub")
    )

    try:
        resource_access = decoded_token.get("resource_access", False)
        authorize_access(
            access=resource_access,
            client_id=app.config["CLIENT_ID"],
            role=app.config["AWS_ROLE_ARN"],
        )
        app.token_queue.put((access_token, session_name))
        html_file_path = os.path.join(base_path, "success_message.html")
    except KCError as e:
        logger.error(e)
        app.token_queue.put(("AuthFailure", "AuthFailure"))
        html_file_path = os.path.join(base_path, "failure_access_prohibited_message.html")

    # Pass token and session name to the main thread
    with open(html_file_path, "r") as file:
        html_content = file.read()

    return html_content


def authorize_access(access: dict, client_id: str, role: str) -> bool:
    """Authorize the request.

    Perform the check that the client_id exists in the resource_access dictionary
    of the access_token and that the specified role is present in its roles list.

    Returns:
        bool: True  (the user should be granted access to the aws role)
              False (the user should not be granted access to the aws role)
    """
    if not isinstance(access, dict):
        raise KCError("Invalid resource_access structure of the access token")

    if client_id not in access:
        raise KCError(f"You're not authorized to access client ID {client_id}")

    if role not in access[client_id].get("roles", []):
        raise KCError(
            f"You're not authorized to assume role {role} which is defined in Client ID {client_id}"
        )

    return True
