import json
import logging
from dataclasses import dataclass
from datetime import datetime
from sys import exit
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger("error")


@dataclass
class AWSCredentials:
    AccessKeyId: str
    SecretAccessKey: str
    SessionToken: str
    Expiration: datetime

    def as_env(self) -> str:
        """
        Return the AWS credentials in the format of shell environment variable export commands.
        """
        return (
            f"export AWS_ACCESS_KEY_ID={self.AccessKeyId}\n"
            f"export AWS_SECRET_ACCESS_KEY={self.SecretAccessKey}\n"
            f"export AWS_SESSION_TOKEN={self.SessionToken}\n"
            f"export AWS_CREDENTIALS_EXPIRATION={self.Expiration.isoformat()}"
        )

    def as_json(self) -> str:
        """
        Return the AWS credentials in JSON format.
        """
        aws_credentials = {
            "Version": 1,
            "AccessKeyId": self.AccessKeyId,
            "SecretAccessKey": self.SecretAccessKey,
            "SessionToken": self.SessionToken,
            "Expiration": self.Expiration.isoformat(),
        }
        return json.dumps(aws_credentials, indent=4)


def assume_aws_role_with_keycloak_token(
    token: str, aws_role_arn: str, session_name: str, session_duration_hours: int = 2
) -> Optional[AWSCredentials]:
    """
    Assume an AWS IAM role using a Keycloak-provided token.

    Args:
        token (str): The Keycloak access token (WebIdentityToken).
        aws_role_arn (str): The Amazon Resource Name (ARN) of the role to
                            assume.
        session_name (str): A name to uniquely identify the assumed session.
        session_duration_hours (int): A session duration in hours.

    Returns:
        Optional[AWSCredentials]: AWS temporary credentials including
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
        credentials = response["Credentials"]
        return AWSCredentials(
            AccessKeyId=credentials["AccessKeyId"],
            SecretAccessKey=credentials["SecretAccessKey"],
            SessionToken=credentials["SessionToken"],
            Expiration=credentials["Expiration"],
        )
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


def export_aws_credentials_env(credentials: AWSCredentials):
    """
    Generate and print AWS temporary credentials in a format compatible with
    shell environment variable exports.

    This function is intended to output the necessary `export` commands for
    AWS credentials, allowing users to quickly set their environment variables
    for temporary access to AWS resources. The output can be used directly
    in a Bash shell by sourcing the command.

    Args:
        credentials (AWSCredentials): A dictionary containing AWS temporary
                                      credentials, which must include:
                                      - 'AccessKeyId': The AWS access key ID.
                                      - 'SecretAccessKey': The AWS secret key.
                                      - 'SessionToken': The AWS session token.
                                      - 'Expiration': The expiration timestamp
                                        (must support `isoformat()`).

    Example Usage:
        This function is typically used in the following way to simplify
        credential management. Example usage in a Bash shell:

            source <(ksso --env \
                --client-id client-name-aws \
                --aws-role-arn arn:aws:iam::account_id:role/some-role-name)

    Output:
        Prints environment variable export commands, which can be directly
        sourced into the shell to configure AWS credentials temporarily
    """
    print(credentials.as_env())


def export_aws_credentials_json(credentials: AWSCredentials):
    """
    Generate and print AWS temporary credentials in a json format.

    This function is intended to output the json object with valid
    aws short term credentials, that can be quickly assumed by tools
    like aws-vault supporting credentials helpers.

    Args:
        credentials (AWSCredentials): A dictionary containing AWS temporary
                                      credentials, which must include:
                                      - 'AccessKeyId': The AWS access key ID.
                                      - 'SecretAccessKey': The AWS secret key.
                                      - 'SessionToken': The AWS session token.
                                      - 'Expiration': The expiration timestamp
                                        (must support `isoformat()`).

    Example Usage:
        This function is typically used in conjunction with a tool like `aws-vault`
        to simplify credential management. See expected aws-vault configuration
        in the documentation.

    Output:
        Prints json object, which can be directly sourced into the shell
        or cli tools like `aws-vault` supporting credential helpers
    """
    print(credentials.as_json())
