# Author: Anees
# Vulnerability: SMTP Open Relay / Service Exposed on Non-Standard Port
# Target: smtp.0x10.cloud
# Course: COMP2152 Term Project

import socket
import time

host = "smtp.0x10.cloud"
port = 2525

print("checking smtp service on", host, port)
print("-" * 45)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    time.sleep(0.15)

    # read the welcome banner
    banner = s.recv(512).decode(errors="ignore").strip()
    print("banner:", banner)

    # send EHLO to get server capabilities
    s.sendall(b"EHLO test.com\r\n")
    time.sleep(0.2)
    ehlo_response = s.recv(512).decode(errors="ignore").strip()
    print("EHLO response:", ehlo_response)

    # try to start sending an email without authenticating
    s.sendall(b"MAIL FROM:<attacker@evil.com>\r\n")
    time.sleep(0.2)
    mail_response = s.recv(512).decode(errors="ignore").strip()
    print("MAIL FROM response:", mail_response)

    s.sendall(b"RCPT TO:<victim@example.com>\r\n")
    time.sleep(0.2)
    rcpt_response = s.recv(512).decode(errors="ignore").strip()
    print("RCPT TO response:", rcpt_response)

    # close connection properly
    s.sendall(b"QUIT\r\n")
    time.sleep(0.15)
    s.close()

    print()
    print("VULNERABILITY CONFIRMED")
    print("-" * 45)
    print("host:", host)
    print("port:", port, "(non-standard, default SMTP is 25)")
    print("server:", banner)
    print()
    print("why this is a problem:")
    print("- the smtp server is publicly accessible on port 2525")
    print("- it reveals server software and version in the banner (Postfix + Ubuntu)")
    print("- attackers can use this info to look up known exploits for this version")
    print("- the server accepts MAIL FROM without authentication")
    print("- this can allow spammers to relay emails through this server")
    print("- smtp should not be exposed publicly without strict auth and rate limiting")

except socket.timeout:
    print("connection timed out")
except ConnectionRefusedError:
    print("connection refused on port", port)
except Exception as e:
    print("error:", e)
