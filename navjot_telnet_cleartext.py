# ============================================================
# Author:      Navjot
# Vulnerability: Telnet Service Exposed (Cleartext Protocol)
# Target:      telnet.0x10.cloud (port 2323)
# Course:      COMP2152 Term Project
# ============================================================
import socket
import time
TARGET = "telnet.0x10.cloud"
PORT = 2323
def check_telnet_exposure(host, port):
    """
    Connect to the Telnet service and confirm it is openly accessible.
    Telnet sends ALL data — including usernames and passwords — in
    plain text, making it trivially interceptable by network sniffers.
    """
    print("=" * 55)
    print("  Vulnerability Check: Exposed Telnet Service")
    print(f"  Target : {host}:{port}")
    print("=" * 55)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        # Step 1 — Attempt TCP connection
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"\n[OPEN] Port {port} is reachable on {host}")
            # Step 2 — Read the Telnet banner the server sends back
            time.sleep(0.3)   # brief pause so banner arrives
            try:
                banner = sock.recv(1024).decode(errors="replace").strip()
                if banner:
                    print(f"[BANNER] Server responded:\n{banner}")
            except Exception:
                print("[INFO] No banner received (connection still open)")
            # Step 3 — Report the vulnerability
            print("\n[!] VULNERABILITY CONFIRMED")
            print("    Name   : Exposed Telnet Service on Non-Standard Port")
            print("    Risk   : Telnet transmits all data — including login")
            print("             credentials — in cleartext. Any attacker with")
            print("             network access can capture usernames and")
            print("             passwords using a packet sniffer (e.g., Wireshark).")
            print("    Fix    : Disable Telnet; use SSH instead.")
        else:
            print(f"[CLOSED] Port {port} is not reachable on {host}")
            print("         No vulnerability found at this location.")
    except socket.timeout:
        print(f"[TIMEOUT] Connection to {host}:{port} timed out.")
    except socket.gaierror as e:
        print(f"[DNS ERROR] Could not resolve {host}: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        sock.close()
    print("=" * 55)
if __name__ == "__main__":
    check_telnet_exposure(TARGET, PORT)