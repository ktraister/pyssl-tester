import ssl
import sys

server = sys.argv[1]
port = sys.argv[2]

#print(server)
#print (port)
print(ssl.get_server_certificate((server, port)))
print()
