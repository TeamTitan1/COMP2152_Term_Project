# ============================================================
# Author:      Navjot Kaur Mathoda
# Vulnerability: Redis Server Exposed (No Authentication)
# Target:      redis.0x10.cloud (port 6379)
# Course:      COMP2152 Term Project
# ============================================================
import socket
import time
TARGET = "redis.0x10.cloud"
PORT = 6379
def check_redis_exposure(host, port):
    """
    Connect to Redis and send a PING command.
    If Redis responds without requiring a password,
    anyone on the internet can read, write, or delete
    all data stored in the database.
    """
    print("=" * 55)
    print("  Vulnerability Check: Unauthenticated Redis Access")
    print(f"  Target : {host}:{port}")
    print("=" * 55)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        # Step 1 — Connect to Redis port
        result = sock.connect_ex((host, port))
        if result != 0:
            print(f"[CLOSED] Port {port} is not reachable on {host}")
            return
        print(f"\n[OPEN] Port {port} is reachable on {host}")
        # Step 2 — Send Redis PING command (no login needed)
        time.sleep(0.15)
        sock.sendall(b"PING\r\n")
        response = sock.recv(1024).decode(errors="replace").strip()
        print(f"[RESPONSE] Server replied: {response}")
        # Step 3 — Try to get server info
        time.sleep(0.15)
        sock.sendall(b"INFO server\r\n")
        info = sock.recv(2048).decode(errors="replace").strip()
        print(f"[INFO] Server info received ({len(info)} bytes)")
        # Step 4 — Check if we got a real Redis response
        if "+PONG" in response or "$" in response or "redis_version" in info:
            print("\n[!] VULNERABILITY CONFIRMED")
            print("    Name   : Unauthenticated Redis Access")
            print("    Risk   : The Redis database requires no password.")
            print("             Any attacker can connect and read, modify,")
            print("             or delete ALL data in the database, and")
            print("             potentially use it to gain server access.")
            print("    Fix    : Set 'requirepass' in redis.conf to enforce")
            print("             authentication before any command is accepted.")
        else:
            print("[OK] Redis did not respond as expected.")
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
    check_redis_exposure(TARGET, PORT)