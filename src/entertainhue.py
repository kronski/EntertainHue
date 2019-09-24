#!/usr/bin/python3

import sys
import socket
from http_parser.parser import HttpParser
import argparse
import requests 
import time
import json

parser = argparse.ArgumentParser()
parser.add_argument("-v","--verbose", dest="verbose", action="store_true")
commandlineargs = parser.parse_args()

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def verbose(*args, **kwargs):
    if commandlineargs.verbose==True:
        print(*args, **kwargs)

def findhue():
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
                    return addr,headers

            if p.is_message_complete():
                break
    except socket.timeout:
        pass
    return None

verbose("Finding bridge...")
(hueip,port),headers = findhue() or ((None,None),None)
if hueip is None:
    eprint("Hue bridge not found.")
    exit
verbose("Bridge found on", hueip)

baseurl = "http://{}/api".format(hueip)

verbose("Requesting bridge information...")
r = requests.get(url = baseurl+"/config") 
jsondata = r.json()

if jsondata["apiversion"]<"1.22":
    eprint("Hue apiversion not 1.22 or above.")
    exit
verbose("Api version good {}...".format(jsondata["apiversion"]))

verbose("Registering on bridge...")
while True:
    r = requests.post(url = baseurl, json={"devicetype":"entertainhue python script","generateclientkey":True}) 
    jsondata = r.json()
    if isinstance(jsondata,list) \
    and "success" in jsondata[0] \
    and jsondata[0]["success"]:
        f = open("client.json", "w")
        f.write(json.dumps(jsondata[0]["success"]))
        f.close()
        break
    
    if isinstance(jsondata,list) \
    and "error" in jsondata[0] \
    and "description" in jsondata[0]["error"]:
        if jsondata[0]["error"]["description"]=="link button not pressed":
            print("Press button on hue device to authorize")
            time.sleep(5)
        else:
            print(jsondata[0]["error"]["description"])

verbose("Authorized")


