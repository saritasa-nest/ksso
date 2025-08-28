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

import requests

from ksso import credstore
from ksso.aws import (
    AWSCredentials,
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
logging.basicConfig(
    level=logging.WARN, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ksso")

# Set boto3 and other libraries to only log errors
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("ksso").setLevel(logging.WARNING)


def logout(client_id: str = None, aws_role_arn: str = None) -> None:
    """
    Logout from keycloak

    This will remove cached credentials from the keyring.

    Args:
        client_id: Optional client ID to filter credentials
        aws_role_arn: Optional role ARN to filter credentials

    If both client_id and aws_role_arn are provided, only credentials matching both will be removed.
    If neither is provided, all cached credentials will be removed.
    """
    if bool(client_id) != bool(aws_role_arn):
        logger.error("--client-id and --aws-role-arn must be specified together")
        exit(1)

    removed_credentials = credstore.logout(client_id, aws_role_arn)
    if removed_credentials > 0:
        if client_id and aws_role_arn:
            print(f"Removed credentials for {client_id} and role {aws_role_arn}")
        else:
            print(f"Removed {removed_credentials} credential(s)")
    else:
        print("No cached credentials found to remove")
    return


def login(config: str, client_id: str, aws_role_arn: str) -> AWSCredentials:
    """
    Login to Keycloak and obtain AWS credentials.

    This function authenticates with Keycloak using OIDC flow and then
    uses the obtained token to assume an AWS IAM role.

    Args:
        config: Path to the KSSO configuration file
        client_id: Keycloak client ID to authenticate with
        aws_role_arn: AWS IAM Role ARN to assume

    Returns:
        AWSCredentials object containing temporary AWS credentials
    """
    logger.info("No valid cached credentials found, starting authentication flow...")
    try:
        ksso_config = load_config(config)
    except ConfigError as e:
        logger.error(e)
        exit(1)
    except (requests.RequestException, requests.exceptions.HTTPError, ValueError) as e:
        logger.error(f"Error while connecting to Keycloak: {e}")
        exit(1)

    # Store dynamic values in Flask app config
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

    # Assume AWS role using the obtained access token and session name
    return assume_aws_role_with_keycloak_token(access_token, aws_role_arn, session_name)


def main():
    """
    Entry point for the application.

    This function:
    1. Checks for valid keyring cached credentials first
    2. If no valid (not expired) credentials, starts the authentication flow:
       - Parses CLI arguments for configuration and options
       - Sets up the Flask server for handling Keycloak's OIDC authentication callback
       - Opens the browser to initiate the Keycloak login flow
       - Waits for authentication to complete and retrieves the access token
       - Uses the access token to assume an AWS IAM role
    3. Outputs the credentials in the requested format
    4. Caches the credentials for future use in the keyring
    """
    parser = argparse.ArgumentParser(
        description="Authenticate via Keycloak and assume an AWS role."
    )

    # Add common arguments
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose (INFO) logging"
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Login command (default)
    login_parser = subparsers.add_parser("login", help="Login and get AWS credentials")
    login_parser.add_argument(
        "--json", action="store_true", help="Output AWS credentials in JSON format."
    )
    login_parser.add_argument(
        "--env",
        action="store_true",
        help="Output AWS credentials in bash source format.",
    )
    login_parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to the TOML config file (default: {DEFAULT_CONFIG_PATH})",
    )
    login_parser.add_argument(
        "--client-id",
        type=str,
        required=True,
        help=(
            "Keycloak client id (typically after the name of the client), "
            "where <name> is the actual client name/prefix"
        ),
    )
    login_parser.add_argument(
        "--aws-role-arn",
        type=str,
        required=True,
        help="AWS IAM Role ARN to assume (e.g., arn:aws:iam::123456789012:role/role-name)",
    )

    # Logout command
    logout_parser = subparsers.add_parser("logout", help="Logout and remove cached AWS credentials")
    logout_parser.add_argument(
        "--client-id",
        type=str,
        help="Keycloak client ID to remove credentials for (removes all if not specified)",
    )
    logout_parser.add_argument(
        "--aws-role-arn",
        type=str,
        help="AWS IAM Role ARN to remove credentials for (requires --client-id)",
    )
    args = parser.parse_args()

    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger("ksso").setLevel(logging.INFO)
        logger.info("Verbose logging enabled")

    # Handle logout command
    if args.command == "logout":
        return logout(args.client_id, args.aws_role_arn)

    # Handle login command (default)
    # First try to get credentials from keyring cache
    credentials = credstore.load_credentials(args.client_id, args.aws_role_arn)

    # If no valid cached credentials, proceed with normal auth flow
    # and save the new credentials to keyring
    if not credentials:
        credentials = login(args.config, args.client_id, args.aws_role_arn)
        credstore.save_credentials(args.client_id, args.aws_role_arn, credentials)

    # Output credentials based on CLI args
    if args.json:
        export_aws_credentials_json(credentials)
    elif args.env:
        export_aws_credentials_env(credentials)
    else:
        # Default to JSON output if no format specified
        export_aws_credentials_json(credentials)


if __name__ == "__main__":
    main()
