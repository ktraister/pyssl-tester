import ssl
import sys
import socket
import hashlib
import re
import OpenSSL
import datetime
import check_tls_certs

flag1=0
flag2=0

if (len(sys.argv)) < 3 or (len(sys.argv)) >= 5 :
    print("Incorrect usage!")
    print("Usage: sslcheck.py hostname/IP port [--cert] [--fingerprint]")
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
    if "b'C'" in certls:
        ccindex = certls.find("b'C'")
        cc = certls[8 + ccindex:]
        cccindex = cc.find("'")
        ccc = cc[:cccindex]
        print("Country: %s" % (ccc))

    #this part manipulates the state
    if "b'ST'" in certls:
        ssindex = certls.find("b'ST'")
        ss = certls[9 + ssindex:]
        sssindex = ss.find("'")
        sss = ss[:sssindex]
        print("State: %s" % (sss))

    #this part for Location!
    if "b'L'" in certls:
        llindex = certls.find("b'L'")
        ll = certls[8 + llindex:]
        lllindex = ll.find("'")
        lll = ll[:lllindex]
        print("Location: %s" % (lll))

    #this part for Organization
    if "b'O'" in certls:
        ooindex = certls.find("b'O'")
        oo = certls[8 + ooindex:]
        oooindex = oo.find("'")
        ooo = oo[:oooindex]
        print("Organization: %s" % (ooo))


    #this part for CName
    if "b'CN'" in certls:
        nnindex = certls.find("b'CN'")
        nn = certls[9 + nnindex:]
        nnnindex = nn.find("'")
        nnn = nn[:nnnindex]
        print("CName: %s" % (nnn))


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
#this code "works", but doesnt work correctly. Smooth this out
try:
    edate = str(x509.get_notAfter())
    #cdate = ("%s-%s-%s" % (edate[2:6], edate[6:8], edate[8:10]))
    cdate = ("%s-%s-%s %s:%s:%s" % (edate[2:6], edate[6:8], edate[8:10], edate[10:12], edate[12:14], edate [14:16]))

    """
    Temporarily removing this code till I can get It fixed
    if str(datetime.datetime.now()) >  cdate:
        print("Certificate is valid!")
    else:
        print("Certificate is NOT valid!")
    """

    print("Certificate Expiry Information:")
    print("---------------------------------")
    print("Year: %s Month: %s Day: %s Time: %s:%s:%s GMT" % (edate[2:6], edate[6:8], edate[8:10], edate[10:12], edate[12:14], edate [14:16]))

    print()
except Exception as g:
    print()
    print("Exception %s" % (g))

#this section started trying to determine ssl versions server accepts
"""
try:
    ssl.wrap_socket((s, PROTOCOL_SSLv23, True, None))
    ssl.get_server_certificate((server, port, ssl.PROTOCOL_TLSv1))
    SSLSocket.cipher(server, port)
except Exception as ssl1:
    print("Exception: %s" % (ssl1))
"""

if flag1 == "--cert" or flag2 == "--cert":
    print("Certificate:")
    print("---------------------")
    print(cert)

if flag1 == "--fingerprint" or flag2 == "--fingerprint":
    print("SHA-1 Fingerprint:")
    print("----------------------")
    print(hashlib.sha1(cert.encode('utf-8')).hexdigest())

#if flag1 or flag2 == "shit":
#    print("shit!")
