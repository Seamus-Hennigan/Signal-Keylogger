import json
import os

# Default configuration
DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 10000,
        "listen_backlog": 1
    },
    "client": {
        "server_host": "127.0.0.1",
        "server_port": 10000,
        "heartbeat_interval": 30,
        "reconnect_delay": 5,
        "connection_timeout": 5
    },
    "keylogger": {
        "buffer_size": 4096,
        "send_on_enter": True
    },
    "logging": {
        "log_directory": "logs/",
        "enable_file_logging": False,
        "log_level": "INFO"
    },
    "gui": {
        "theme": "dark",
        "window_title": "Signal Keylogger Dashboard"
    }
}


class Config:
    """Configuration manager with JSON file support and defaults"""

    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.config = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        """Load configuration from file, create with defaults if not exists"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults (in case new keys added)
                    self._deep_merge(self.config, loaded_config)
                print(f"[Config] Loaded from {self.config_file}")
            except Exception as e:
                print(f"[Config] Error loading {self.config_file}: {e}")
                print(f"[Config] Using default configuration")
        else:
            print(f"[Config] No config file found, creating default at {self.config_file}")
            self.save()

    def save(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"[Config] Saved to {self.config_file}")
        except Exception as e:
            print(f"[Config] Error saving config: {e}")

    def get(self, *keys):
        """Get config value by nested keys. Example: config.get('server', 'port')"""
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def set(self, *keys, value):
        """Set config value by nested keys. Example: config.set('server', 'port', value=8080)"""
        if len(keys) < 1:
            return

        current = self.config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def _deep_merge(self, base, update):
        """Recursively merge update dict into base dict"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = DEFAULT_CONFIG.copy()
        self.save()


# Global config instance
config = Config()


# Convenience functions
def get_server_config():
    return config.get('server')


def get_client_config():
    return config.get('client')


def get_keylogger_config():
    return config.get('keylogger')


def get_logging_config():
    return config.get('logging')


def get_gui_config():
    return config.get('gui')