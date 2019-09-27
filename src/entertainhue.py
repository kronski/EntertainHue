#!/usr/bin/python3

import sys
from http_parser.parser import HttpParser
import argparse
import requests 
import time
import json
from pathlib import Path
import ssl
from socket import socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP, timeout
from dtls import do_patch
import sslpsk
import binascii
import subprocess
import threading
import random

parser = argparse.ArgumentParser()
parser.add_argument("-v","--verbose", dest="verbose", action="store_true")
parser.add_argument("-g","--groupid", dest="groupid")
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
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
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
    except timeout:
        pass
    return None

def execute(cmd):
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        yield stdout_line 
    popen.stdout.close()
    return_code = popen.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)

verbose("Finding bridge...")
(hueip,port),headers = findhue() or ((None,None),None)
if hueip is None:
    sys.exit("Hue bridge not found.")
verbose("Bridge found on", hueip)

baseurl = "http://{}/api".format(hueip)

verbose("Requesting bridge information...")
r = requests.get(url = baseurl+"/config") 
jsondata = r.json()

if jsondata["apiversion"]<"1.22":
    sys.exit("Hue apiversion not 1.22 or above.")
verbose("Api version good {}...".format(jsondata["apiversion"]))

verbose("Checking for client.json")
if Path("./client.json").is_file():
    f = open("client.json", "r")
    jsonstr = f.read()
    clientdata = json.loads(jsonstr)
    f.close()
    verbose("Client data found", clientdata)

if not isinstance(clientdata,object):
    verbose("Registering on bridge...")
    while True:
        r = requests.post(url = baseurl, json={"devicetype":"entertainhue python script","generateclientkey":True}) 
        jsondata = r.json()
        if isinstance(jsondata,list) \
        and "success" in jsondata[0] \
        and jsondata[0]["success"]:
            clientdata = jsondata[0]["success"]
            f = open("client.json", "w")
            f.write(json.dumps(clientdata))
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


#r = requests.post(url = baseurl+"{}/groups".format(clientdata['username']), json={"type": "Entertainment","lights": ["1"],"class": "TV"}) 
r = requests.get(url = baseurl+"{}/groups".format(clientdata['username'])) 
jsondata = r.json()
groups = dict()
groupid = commandlineargs.groupid
if groupid is not None:
    verbose("Checking for entertainment group {}".format(groupid))
else:
    verbose("Checking for entertainment groups")
for k in jsondata:
    if jsondata[k]["type"]=="Entertainment":
        if groupid is None or k==groupid:
            groups[k] = jsondata[k]
if len(groups)==0:
    if groupid is not None:
        sys.exit("Entertainment group not found")
    else:
        sys.exit("No entertainment group found")
if len(groups)>1:
    eprint("Multiple entertainment groups found, specify which with --groupid")
    for g in groups:
        eprint("{} = {}".format(g,groups[g]["name"]))
    sys.exit()
if groupid is None:
    groupid=next(iter(groups))
verbose("Using groupid={}".format(groupid))


r = requests.get(url = baseurl+"{}/groups/{}".format(clientdata['username'],groupid))
jsondata = r.json()
print(jsondata)


verbose("Enabling streaming on group")
r = requests.put(url = baseurl+"{}/groups/{}".format(clientdata['username'],groupid),json={"stream":{"active":True}}) 
jsondata = r.json()
verbose(jsondata)

def output_reader(proc):
    #for line in iter(proc.stdout.readline, b''):
    #    if not line:
    #        break
    #    print('got line: {0}'.format(line), end='')
    print('x')

def output_writer(proc):
    while True:

        rgb1 = bytearray([random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255)])
        rgb2 = bytearray([random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255)])

        # message = bytes('HueStream','utf-8')+b'\1\0\0\0\0\0\0'+b'\0\0\x0B\xFF\xFF\x00\x00\x00\x00'+b'\0\0\x0C\xFF\xFF\x00\x00\xFF\xFF'
        message = bytes('HueStream','utf-8')+b'\1\0\0\0\0\0\0'+b'\0\0\x0B'+rgb1+b'\0\0\x0C'+rgb2
        #                                      V V S R R C R 
        print(len(message))
        proc.stdin.write(message)
        proc.stdin.flush()
        print("sent")
        time.sleep(.2)

try:
    #do_patch()

    #verbose('Unhexing clientkey')
    #clientkey = binascii.unhexlify(clientdata['clientkey'])
    #verbose(clientdata['clientkey'],"=>", clientkey)

    # sock = sslpsk.wrap_socket(socket(AF_INET, SOCK_DGRAM),psk=(clientdata['username'],clientkey))
    # sock.connect((hueip, 2100))
    # sock.close()
    # result = subprocess.run(['ls', '-l'], stdout=subprocess.PIPE)
    # print(result.stdout)

    #for path in execute(["openssl","s_client","-dtls1_2","-cipher","DHE-PSK-AES256-GCM-SHA384","-psk_identity",clientdata['username'],"-psk",clientdata['clientkey'], "-connect", hueip+":2100"]):
    #    print(path, end="")
    try:
        cmd = ["openssl","s_client","-dtls1_2","-cipher","DHE-PSK-AES256-GCM-SHA384","-psk_identity",clientdata['username'],"-psk",clientdata['clientkey'], "-connect", hueip+":2100"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=False)

        print(proc.stdin)

        reader = threading.Thread(target=output_reader, args=(proc,))
        writer = threading.Thread(target=output_writer, args=(proc,))
        reader.start()
        writer.start()

        input("Press return to stop")
        proc.stdin.close()

        reader.join()
        writer.join()
    except Exception as e:
        print(e)

    # input("Press Enter to continue...")
finally:
    verbose("Disabling streaming on group")
    r = requests.put(url = baseurl+"{}/groups/{}".format(clientdata['username'],groupid),json={"stream":{"active":False}}) 
    jsondata = r.json()
    verbose(jsondata)