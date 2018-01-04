import ssl
import sys
import socket

server = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket()

print("Testing port...")

try:
    s.connect((server, port))
    print("connection succeeded!")
    print()
    ssl
    print("Certificate:")
    print(ssl.get_server_certificate((server, port)))
    print()
except Exception as e:
    print("Could not connect to %s:%d" % (server, port))
    print("Exception: %s" % (e))
finally:
    s.close

