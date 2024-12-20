import os

import toml


def load_config(config_path: str):
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
    return toml.load(config_path)
