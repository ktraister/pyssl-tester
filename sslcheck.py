import ssl
import sys
import socket
import re
import OpenSSL


if (len(sys.argv)) < 3:
    print("Too few args!")
    print("Usage: sslcheck.py hostname/IP port")
    quit()

server = sys.argv[1]
port = int(sys.argv[2])
#fprint = sys.argv[3]
s = socket.socket()
#cert = ssl.get_server_certificate((server, port))
#x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

print()
print("Testing port...")

try:
    s.connect((server, port))
    #socket.socket().connect((server, port))
    print("Connection succeeded!")
    print()
except:
    print("Connection failed!")
    print()
finally:
    s.close

try:
    print("Testing for SSL listener...")
    cert = ssl.get_server_certificate((server, port))
    print("Port is listening for SSL connections!")
    print()
except Exception as e:
    print("OpenSSL connection failed!")
    print("Exception: %s" % (e))
    print()

try:
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    certls = str(x509.get_subject().get_components())

    print("x509 Cert Details:")
    print("----------------------")

    #this part of the code manipulates the return of x509.get_subject()
    cc = certls.split(')', 1)[0].rstrip()
    ccc = cc.split('b', 2)[2]
    print("Country: %s" % (ccc))

    #this part manipulates the state
    ss = certls.split(')', 2)[1].rstrip()
    sss = ss.split('b', 2)[2]
    print("State: %s" % (sss))

    #this part for L?
    ll = certls.split(')', 3)[2].rstrip()
    lll = ll.split('b', 2)[2]
    print("Location: %s" % (lll))

    #this part for Organization
    oo = certls.split(')', 4)[3].rstrip()
    ooo = oo.split('b', 2)[2]
    print("Organization: %s" % (ooo))

    #this part for CName
    cn = certls.split(')', 5)[4].rstrip()
    cnn = cn.split('b', 2)[2]
    print("CName: %s" % (cnn))

    print()

except Exception as f:
    print()
    print("Failed getting x509 cert details!")
    print("Here's what I got:")
    print(certls)
    print()
    print("Exception: %s" % (f))
    print()

#print(cert)
#    print(cert)

