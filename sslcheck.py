import ssl
import sys
import socket
import hashlib
import re
import OpenSSL
import datetime

flag1=0
flag2=0

if (len(sys.argv)) < 3:
    print("Too few args!")
    print("Usage: sslcheck.py hostname/IP port")
    quit()

if len(sys.argv) == 4:
    flag1=sys.argv[3]

if len(sys.argv) == 5:
    flag1=sys.argv[3]
    flag2=sys.argv[4]

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

#this section started trying to determine date of expiration for ssl certs
#try:
    #dcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,  cert)
    #datetime.datetime.strptime(dcert.get_notAfter(), "%Y%m%d%H%M%SZ")
    #exp_date = datetime.datetime.strptime(getpeercert.get_notAfter(), "%Y%m%d%H%M%SZ")
    #print(exp_date)
#except Exception as g:
    #print()
    #print("Exception %s" % (g))

#this section started trying to determine ssl versions server accepts
#try:
    #ssl.get_server_certificate((server, port, ssl_version=ssl.PROTOCOL_TLSv1))
    #SSLSocket.cipher(server, port)
#except Exception as ssl1:
    #print("Exception: %s" % (ssl1))

if flag1 or flag2 == "--cert":
    print("Certificate:")
    print("---------------------")
    print(cert)

if flag1 or flag2 == "--fingerprint":
    print("SHA-1 Fingerprint:")
    print("----------------------")
    print(hashlib.sha1(cert.encode('utf-8')).hexdigest())

#if flag1 or flag2 == "shit":
#    print("shit!")
