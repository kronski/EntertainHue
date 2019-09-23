#!/usr/bin/python3

import socket

from http_parser.parser import HttpParser


msg = \
    'M-SEARCH * HTTP/1.1\r\n' \
    'HOST:239.255.255.250:1900\r\n' \
    'ST:upnp:rootdevice\r\n' \
    'MX:2\r\n' \
    'MAN:"ssdp:discover"\r\n' \
    '\r\n'

# Set up UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.settimeout(5)
s.sendto(msg.encode('utf-8'), ('239.255.255.250', 1900) )

try:
    while True:
        data, addr = s.recvfrom(65507)
        p = HttpParser()
        recved = len(data)
        nparsed = p.execute(data, recved)
        assert nparsed == recved
        if p.is_headers_complete():
            headers = p.get_headers()
            if 'hue-bridgeid' in headers:
                print(addr)
                for key in headers:
                    print("\t",key,":",headers[key])
                break

        if p.is_message_complete():
            break
except socket.timeout:
    pass