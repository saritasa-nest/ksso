"""
┌──────────────────────────────────────────────────────────────────────────┐
│ KSSO                                                                     │
│ ----                                                                     │
│ This is a small CLI application that helps authenticate keycloak         │
│ users into AWS via OIDC.                                                 │
│                                                                          │
│ We obtain a token from keycloak, then we obtain short-term IAM           │
│ credential by assuming role with web-indentity token.                    │
│                                                                          │
│ The AWS role to assume should contain proper trust policy for the        │
│ identity provider associated with the keycloak instance.                 │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
"""

import argparse
import logging
import os
import threading
import webbrowser
from queue import Queue
from sys import exit

import jwt
import requests

from ksso.aws import (
    assume_aws_role_with_keycloak_token,
    export_aws_credentials_env,
    export_aws_credentials_json,
)
from ksso.config import ConfigError, load_config
from ksso.server import app

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.ksso_config.toml")

# Thread-safe queue for inter-thread communication as we need to pass
# from the web-server thread back into the main process
token_queue = Queue()
app.token_queue = token_queue
logger = logging.getLogger("error")


def main():
    """
    Entry point for the application.

    This function:
    1. Parses CLI arguments for configuration and options.
    2. Sets up the Flask server for handling Keycloak's OIDC authentication
       callback.
    3. Opens the browser to initiate the Keycloak login flow.
    4. Waits for authentication to complete and retrieves the access token.
    5. Uses the access token to assume an AWS IAM role and outputs credentials.
    """
    parser = argparse.ArgumentParser(
        description="Authenticate via Keycloak and assume an AWS role."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output AWS credentials in JSON format."
    )
    parser.add_argument(
        "--env",
        action="store_true",
        help="Output AWS credentials in bash source format.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to the TOML config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--client-id",
        type=str,
        required=True,
        help=(
            "Keycloak client id (typically after the name of the client), "
            "where <name> is the actual client name/prefix"
        ),
    )
    parser.add_argument(
        "--aws-role-arn",
        type=str,
        required=True,
        help="AWS IAM Role ARN to assume (e.g., arn:aws:iam::123456789012:role/role-name)",
    )
    args = parser.parse_args()

    try:
        ksso_config = load_config(args.config)
    except ConfigError as e:
        logger.error(e)
        exit(1)
    except (requests.RequestException, requests.exceptions.HTTPError, ValueError) as e:
        logger.error(f"Error while connecting to Keycloak: {e}")
        exit(1)

    # Store dynamic values in Flask app config
    client_id, aws_role_arn = args.client_id, args.aws_role_arn
    app.config["KEYCLOAK_URL"] = ksso_config.sso_token_service_url
    app.config["REDIRECT_URI"] = ksso_config.sso_redirect_url
    app.config["CLIENT_ID"] = client_id
    app.config["AWS_ROLE_ARN"] = aws_role_arn

    # Start Flask app in a separate thread
    threading.Thread(target=lambda: app.run(port=ksso_config.sso_agent_port), daemon=True).start()

    # Open the browser for authentication
    webbrowser.open(f"http://localhost:{ksso_config.sso_agent_port}/")

    # Wait for the token and session name to be available in the queue
    access_token, session_name = token_queue.get()
    if os.environ.get("DEBUG"):
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        print(decoded_token)

    # Assume AWS role using the obtained access token and session name
    credentials = assume_aws_role_with_keycloak_token(access_token, aws_role_arn, session_name)

    # Output credentials based on CLI args
    if args.json:
        export_aws_credentials_json(credentials)
    elif args.env:
        export_aws_credentials_env(credentials)


if __name__ == "__main__":
    main()
