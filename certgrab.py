import ssl

server = input("Which server should I grab a cert from? ")
print()
port = input("How about a port? ")
print()

print(ssl.get_server_certificate((server, port)))
print()
