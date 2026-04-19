# ============================================================
<<<<<<< HEAD
# Author:      Saurab Bhattarai
=======
# Author:      Saurab
>>>>>>> 40db524 (Add anonymous ftp login allowed script for ftp.0x10.cloud)
# Vulnerability: Anonymous FTP Login Allowed
# Target:      ftp.0x10.cloud (port 2121)
# Course:      COMP2152 Term Project
# ============================================================

import socket
import time

TARGET = "ftp.0x10.cloud"
PORT = 2121


def recv_response(sock):
    """
    Read a full response from the FTP server.
    FTP responses end when a line starts with a 3-digit code + space.
    """
    response = ""
    while True:
        try:
            chunk = sock.recv(4096).decode(errors="replace")
            response += chunk

            lines = response.strip().splitlines()
            if lines and len(lines[-1]) >= 4 and lines[-1][3] == " ":
                break

        except Exception:
            break

    return response.strip()


def send_command(sock, command):
    """Send an FTP command and return the response."""
    time.sleep(0.15)  # Respect rate limit
    sock.sendall((command + "\r\n").encode())
    return recv_response(sock)


def check_anonymous_ftp(host, port):
    print("=" * 55)
    print("  Vulnerability Check: Anonymous FTP Access")
    print(f"  Target : {host}:{port}")
    print("=" * 55)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(8)

    try:
        # Step 1 — Connect
        sock.connect((host, port))
        banner = recv_response(sock)
        print(f"\n[CONNECTED] Server banner:\n{banner}")

        # Step 2 — Send USER
        resp_user = send_command(sock, "USER anonymous")
        print(f"\n[>] USER anonymous\n[<] {resp_user}")

        # Step 3 — Send PASS
        resp_pass = send_command(sock, "PASS guest@example.com")
        print(f"\n[>] PASS guest@example.com\n[<] {resp_pass}")

        # Step 4 — Check success
        if resp_pass.startswith("230"):
            print("\n[!] VULNERABILITY CONFIRMED")
            print("    Name   : Anonymous FTP Login Allowed")
            print("    Risk   : Anyone can log in without credentials")
            print("             and access files on the server.")
            print("    Fix    : Disable anonymous FTP access.")

            # Try listing files (proof)
            resp_pasv = send_command(sock, "PASV")
            print(f"\n[>] PASV\n[<] {resp_pasv}")

            resp_list = send_command(sock, "LIST")
            print(f"\n[>] LIST\n[<] {resp_list}")

        else:
            print("\n[OK] Anonymous login rejected — not vulnerable.")

        # Step 5 — Quit
        send_command(sock, "QUIT")

    except socket.timeout:
        print(f"[TIMEOUT] Connection to {host}:{port} timed out.")

    except socket.gaierror as e:
        print(f"[DNS ERROR] Could not resolve {host}: {e}")

    except ConnectionRefusedError:
        print(f"[REFUSED] Connection refused on {host}:{port}")

    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

    finally:
        sock.close()

    print("=" * 55)


if __name__ == "__main__":
    check_anonymous_ftp(TARGET, PORT)