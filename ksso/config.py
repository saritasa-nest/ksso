import os
from dataclasses import dataclass

import toml


@dataclass
class KeycloakConfig:
    sso_domain: str
    sso_realm: str
    sso_agent_port: int


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
