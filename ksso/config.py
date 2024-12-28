import os
from dataclasses import dataclass

import requests
import toml


@dataclass
class KeycloakConfig:
    """
    Configuration class for Keycloak Single Sign-On (SSO) integration.

    Attributes:
        sso_domain (str): The domain of the Keycloak server (e.g., 'keycloak.example.com').
        sso_realm (str): The name of the Keycloak realm used for authentication.
        sso_agent_port (int): The port used by the ksso server for communication.
        sso_redirect_url (str): The URL where Keycloak will redirect users after authentication.
        sso_realm_url (str): The full URL of the Keycloak realm
            (e.g., 'https://keycloak.example.com/realms/<realm>').
        sso_token_service_url (str): The URL of the Keycloak realm token service endpoint
            for obtaining tokens.
    """

    def __init__(self, sso_domain: str, sso_realm: str, sso_agent_port: int):
        self.sso_domain = sso_domain
        self.sso_realm = sso_realm
        self.sso_agent_port = sso_agent_port
        self.sso_redirect_url = f"http://localhost:{self.sso_agent_port}/callback"
        self.sso_realm_url = f"{self.sso_domain}/realms/{self.sso_realm}"

        response = requests.get(self.sso_realm_url, timeout=5)
        response.raise_for_status()
        realm_data = response.json()
        self.sso_token_service_url = realm_data.get("token-service")

        if not self.sso_token_service_url:
            raise ConfigError("Error: Keycloak 'token-service' is not found in keycloak response.")


class ConfigError(Exception):
    """Custom exception for configuration errors."""

    pass


def load_config(config_path: str) -> KeycloakConfig:
    """Load Keycloak configuration from a TOML file with validation."""
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at '{config_path}'.")
        print("Please create a configuration file in the following format:")
        example_config = {
            "sso": {
                "sso_domain": "https://keycloak.domain.com",
                "sso_realm": "your-realm-name",
                "sso_agent_port": 5000,
            }
        }
        print(toml.dumps(example_config))
        exit(1)

    config = toml.load(config_path)
    keycloak_config = config.get("sso")

    if keycloak_config:
        return KeycloakConfig(
            sso_domain=keycloak_config.get("sso_domain"),
            sso_realm=keycloak_config.get("sso_realm"),
            sso_agent_port=keycloak_config.get("sso_agent_port"),
        )

    raise ConfigError(f"Error: Missing 'sso' section in the configuration file at {config_path}")
