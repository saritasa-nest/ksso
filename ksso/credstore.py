import base64
import logging
import pickle
from datetime import datetime
from typing import Optional

import keyring

from ksso.aws import AWSCredentials

logger = logging.getLogger(__name__)

KEYRING_SERVICE = "ksso-aws-credentials"


def get_cache_key(client_id: str, role_arn: str) -> str:
    """Generate a unique key for storing credentials in the keyring."""
    return f"{client_id}||{role_arn}"


def load_credentials(client_id: str, role_arn: str) -> Optional[AWSCredentials]:
    """Load cached credentials from the keyring if they exist and are not expired.

    Returns:
        The deserialized credentials object (typically AWSCredentials) or None if not found/expired
    """
    try:
        cache_key = get_cache_key(client_id, role_arn)
        tmp_creds = keyring.get_password(KEYRING_SERVICE, cache_key)

        # if we don't have credentials, process with regular auth flow
        if not tmp_creds:
            return None

        pickled_creds = base64.b64decode(tmp_creds.encode("utf-8"))

        creds = pickle.loads(pickled_creds)
        expiration_ltz = creds.Expiration.astimezone().isoformat()

        if datetime.now(creds.Expiration.tzinfo) < creds.Expiration:
            logger.info(f"Using valid cached credentials that have not expired: {expiration_ltz}")
            return creds

        logger.info(f"Cached credentials have expired: {expiration_ltz}")
        return None
    except Exception as e:
        logger.warning(f"Failed to load credentials from keyring: {e}", exc_info=True)
        return None


def save_credentials(client_id: str, role_arn: str, credentials: AWSCredentials) -> None:
    """Save credentials to the keyring with expiration time.

    Args:
        client_id: The client ID for the credentials
        role_arn: The AWS role ARN
        credentials: The credentials object to save (will be pickled)
    """
    try:
        cache_key = get_cache_key(client_id, role_arn)
        pickled_creds = base64.b64encode(pickle.dumps(credentials)).decode("utf-8")

        keyring.set_password(KEYRING_SERVICE, cache_key, pickled_creds)
        logger.info("Successfully saved credentials to keyring")
    except Exception as e:
        logger.warning(f"Failed to save credentials to keyring: {e}", exc_info=True)


def logout(client_id: Optional[str] = None, role_arn: Optional[str] = None) -> int:
    """Remove cached credentials from the keyring.

    Args:
        client_id: Optional client ID to filter credentials
        role_arn: Optional role ARN to filter credentials

    Returns:
        int: Number of credentials removed
    """
    try:
        # If both client_id and role_arn are provided, delete specific credential
        removed = 0
        if client_id and role_arn:
            cache_key = get_cache_key(client_id, role_arn)
            if keyring.get_password(KEYRING_SERVICE, cache_key):
                keyring.delete_password(KEYRING_SERVICE, cache_key)
                removed += 1
            return removed

        # if not client_id and role_arn are provided, delete all credentials
        if hasattr(keyring, "get_credential"):
            cred = keyring.get_credential(KEYRING_SERVICE, None)
            if cred:
                try:
                    keyring.delete_password(KEYRING_SERVICE, cred.username)
                    removed += 1
                except Exception as e:
                    logger.warning(f"Error processing credential: {e}", exc_info=True)
        return removed

    except Exception as e:
        logger.error(f"Error during clearing credentials: {e}", exc_info=True)
        return 0
