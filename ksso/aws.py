import json
import logging
from sys import exit

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger("stderr_logger")


def assume_aws_role_with_keycloak_token(
    token, aws_role_arn, session_name, session_duration_hours=2
):
    """Assume an AWS IAM role using a Keycloak-provided token.

    Args:
        token (str): The Keycloak access token (WebIdentityToken).
        aws_role_arn (str): The Amazon Resource Name (ARN) of the role to
                            assume.
        session_name (str): A name to uniquely identify the assumed session.

    Returns:
        Optional[Dict[str, str]]: AWS temporary credentials including
        AccessKeyId, SecretAccessKey, SessionToken, and Expiration, or
        None on failure.

    Exceptions:
        Handles and prints AWS-specific errors, general SDK errors,
        and unexpected errors.
    """
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role_with_web_identity(
            RoleArn=aws_role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=token,
            DurationSeconds=session_duration_hours * 3600,
        )
        return response["Credentials"]
    except ClientError as e:
        # Handle AWS-specific errors
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"Failed to assume role {aws_role_arn}: {error_code} - {error_message}")
        exit(1)
    except BotoCoreError as e:
        # General BotoCore errors
        logger.error(f"An error occurred with AWS SDK: {e}")
        exit(1)
    except Exception as e:
        # Catch other unexpected exceptions
        logger.error(f"An unexpected error occurred: {str(e)}")
        exit(1)
    return None


def export_aws_credentials_env(credentials):
    """Print AWS temporary credentials in an environment variable-friendly
    format.

    Args:
        credentials (Dict[str, str]): AWS credentials with AccessKeyId,
                                      SecretAccessKey, SessionToken, and
                                      Expiration.

    Prints:
        Environment variable export commands that can be used in a
        Bash shell via source:

        source <(ksso --env \
            --client-id client-name-aws \
            --aws-role-arn arn:aws:iam::account_id:role/some-role-name
        )
    """
    print(f'export AWS_ACCESS_KEY_ID={credentials["AccessKeyId"]}')
    print(f'export AWS_SECRET_ACCESS_KEY={credentials["SecretAccessKey"]}')
    print(f'export AWS_SESSION_TOKEN={credentials["SessionToken"]}')
    print(f'export AWS_CREDENTIALS_EXPIRATION={credentials["Expiration"].isoformat()}')


def export_aws_credentials_json(credentials):
    """Print AWS temporary credentials in JSON format.

    Args:
        credentials (Dict[str, str]): AWS credentials with AccessKeyId,
                                      SecretAccessKey, SessionToken, and
                                      Expiration.

    Prints:
        JSON-formatted AWS credentials.
    """
    aws_credentials = {
        "AccessKeyId": credentials["AccessKeyId"],
        "SecretAccessKey": credentials["SecretAccessKey"],
        "SessionToken": credentials["SessionToken"],
        "Expiration": credentials["Expiration"].isoformat(),
    }
    print(json.dumps(aws_credentials, indent=4))
