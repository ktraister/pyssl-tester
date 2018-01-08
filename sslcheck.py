import ssl
import sys
import socket
#import hashlib
#import re
import OpenSSL

flag=0

if (len(sys.argv)) < 3 or (len(sys.argv)) >= 5 :
    print("Incorrect usage!")
    print("Usage: sslcheck.py hostname/IP port [--cert]")
    quit()

if len(sys.argv) == 4:
    flag=sys.argv[3]

server = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket()

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
    quit()
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
    quit()

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

    #this part for Location!
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

if flag == "--cert":
    print(cert)

#if flag == "--fingerprint":
#    print(hashlib.sha1(cert).hexdigest())

