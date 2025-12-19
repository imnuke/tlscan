"""Configuration loader for LLM API credentials and settings."""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


class LLMConfig:
    """LLM configuration manager that loads from YAML file."""

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the configuration loader.

        Args:
            config_path: Path to the YAML config file. Defaults to llm_config.yaml in project root.
        """
        if config_path is None:
            # Default to llm_config.yaml in the project root
            # Path: src/tlscan/config/loader.py -> project_root/llm_config.yaml
            config_path = Path(__file__).parent.parent.parent.parent / "llm_config.yaml"

        self.config_path = config_path
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self):
        """Load and parse the YAML configuration file."""
        if not self.config_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}\n"
                f"Please create it based on llm_config.example.yaml"
            )

        try:
            with open(self.config_path, 'r') as f:
                self._config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse YAML config: {e}")

        if not self._config:
            raise ConfigurationError("Configuration file is empty")

        if 'providers' not in self._config:
            raise ConfigurationError(
                "Configuration file must contain 'providers' section"
            )

    def get_provider_config(self, provider: str) -> Dict[str, str]:
        """
        Get configuration for a specific provider.

        Args:
            provider: Provider name (e.g., 'deepseek', 'openai', 'anthropic')

        Returns:
            Dictionary with 'api_key' and optionally 'api_base'

        Raises:
            ConfigurationError: If provider not configured or missing required fields
        """
        providers = self._config.get('providers', {})

        if provider not in providers:
            available = ', '.join(providers.keys()) if providers else 'none'
            raise ConfigurationError(
                f"Provider '{provider}' not found in configuration.\n"
                f"Available providers: {available}\n"
                f"Please add '{provider}' to {self.config_path}"
            )

        provider_config = providers[provider]

        if not isinstance(provider_config, dict):
            raise ConfigurationError(
                f"Provider '{provider}' configuration must be a dictionary"
            )

        if 'api_key' not in provider_config:
            raise ConfigurationError(
                f"Provider '{provider}' is missing required 'api_key' field"
            )

        api_key = provider_config['api_key']
        if not api_key or not isinstance(api_key, str):
            raise ConfigurationError(
                f"Provider '{provider}' has invalid 'api_key' value"
            )

        # Return config with api_key and optional api_base
        config = {'api_key': api_key}

        if 'api_base' in provider_config:
            api_base = provider_config['api_base']
            if api_base and isinstance(api_base, str):
                config['api_base'] = api_base

        return config

    def list_providers(self) -> list[str]:
        """
        Get list of configured providers.

        Returns:
            List of provider names
        """
        return list(self._config.get('providers', {}).keys())

    def get_default_temperature(self) -> float:
        """
        Get the global default temperature setting.

        Returns:
            Temperature value (0.0-2.0). Defaults to 0.7 if not configured.

        Raises:
            ConfigurationError: If temperature value is invalid
        """
        temperature = self._config.get('temperature', 0.7)

        if not isinstance(temperature, (int, float)):
            raise ConfigurationError(
                f"Temperature must be a number, got {type(temperature).__name__}"
            )

        if not (0.0 <= temperature <= 2.0):
            raise ConfigurationError(
                f"Temperature must be between 0.0 and 2.0, got {temperature}"
            )

        return float(temperature)

    def get_agent_temperature(self, agent_type: str) -> float:
        """
        Get the temperature setting for a specific agent type.

        Args:
            agent_type: Agent type ('ssl_analysis', 'dataflow', 'firmware_exploration', 'synthesis')

        Returns:
            Temperature value for the agent, or default temperature if not specified

        Raises:
            ConfigurationError: If temperature value is invalid
        """
        agent_temps = self._config.get('agent_temperatures', {})

        if not isinstance(agent_temps, dict):
            raise ConfigurationError(
                "agent_temperatures must be a dictionary"
            )

        # Use agent-specific temperature if configured, otherwise use default
        if agent_type in agent_temps:
            temperature = agent_temps[agent_type]

            if not isinstance(temperature, (int, float)):
                raise ConfigurationError(
                    f"Temperature for '{agent_type}' must be a number, "
                    f"got {type(temperature).__name__}"
                )

            if not (0.0 <= temperature <= 2.0):
                raise ConfigurationError(
                    f"Temperature for '{agent_type}' must be between 0.0 and 2.0, "
                    f"got {temperature}"
                )

            return float(temperature)

        # Fall back to default temperature
        return self.get_default_temperature()


# Global config instance (lazy loaded)
_global_config: Optional[LLMConfig] = None


def get_config(config_path: Optional[Path] = None) -> LLMConfig:
    """
    Get the global configuration instance.

    Args:
        config_path: Optional custom path to config file

    Returns:
        LLMConfig instance
    """
    global _global_config

    if _global_config is None or config_path is not None:
        _global_config = LLMConfig(config_path)

    return _global_config
