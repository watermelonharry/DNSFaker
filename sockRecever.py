# -*- coding: utf-8 -*-

import socket
import sys

def writeToFile(content, fileName):
    fileName = '//'.join(fileName.split('\\'))
    content = content.split('<*>')
    with open(fileName, 'wb') as f:
        for line in content:
            f.write(line)

def receiver(host, filename, port= 54321):
    try:
        recer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recer.bind(('0.0.0.0', port))
        con, addr = recer.recvfrom(10)

        print('[*]data size received:'+ con)
        recer.settimeout(10)
        recer.sendto('Y', addr)
        data, addr = recer.recvfrom(int(con) + 100)
        writeToFile(data, filename)
        print('[*]file rec done:'+ str(len(data)))

    except Exception as e:
        print('[*]error in rec:'+ str(e))

if __name__ == '__main__':
    host = str(sys.argv[1])
    filename = str(sys.argv[2])
    receiver(host, filename)