#!/usr/bin/python3

import sys
try:
    from http_parser.parser import HttpParser  # pylint: disable=no-name-in-module
except ImportError:
    from http_parser.pyparser import HttpParser
import argparse
import requests 
import time
import json
from pathlib import Path
from socket import socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP, timeout
import subprocess
import threading
import random
import fileinput
import picamera
import picamera.array
import numpy as np
import errno

parser = argparse.ArgumentParser()
parser.add_argument("-v","--verbose", dest="verbose", action="store_true")
parser.add_argument("-s","--send", dest="sendtolight", action="store_true")
parser.add_argument("-r","--random", dest="random", action="store_true")
parser.add_argument("-c","--picamera", dest="picamera", action="store_true")
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


verbose("Enabling streaming on group")
r = requests.put(url = baseurl+"{}/groups/{}".format(clientdata['username'],groupid),json={"stream":{"active":True}}) 
jsondata = r.json()
verbose(jsondata)

bufferlock = threading.Lock()
stopped = False
rgb1 = bytearray([255,255,255,255,255,255])
rgb2 = bytearray([255,255,255,255,255,255])
camera = None

def stdin_to_buffer():
    for line in fileinput.input():
        print(line)
        if stopped:
            break

def random_to_buffer():
    global rgb1
    global rgb2
    while not stopped:
        bufferlock.acquire()
        rgb1 = bytearray([random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255)])
        rgb2 = bytearray([random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255)])
        bufferlock.release()
        time.sleep(.1)
        
def buffer_to_light(proc):
    while not stopped:
        # message = bytes('HueStream','utf-8')+b'\1\0\0\0\0\0\0'+b'\0\0\x0B\xFF\xFF\x00\x00\x00\x00'+b'\0\0\x0C\xFF\xFF\x00\x00\xFF\xFF'
        bufferlock.acquire()
        message = bytes('HueStream','utf-8')+b'\1\0\0\0\0\0\0'+b'\0\0\x0B'+rgb1+b'\0\0\x0C'+rgb2
        bufferlock.release()
        #                                      V V S R R C R 
        proc.stdin.write(message)
        proc.stdin.flush()
        time.sleep(.2)

class MyAnalysis(picamera.array.PiRGBAnalysis):
    def __init__(self, camera):
        super(MyAnalysis, self).__init__(camera)
        self.frame_num = 0
        self.halfwidth = camera.resolution[0]>>1

    def analyse(self, a):
        global rgb1
        global rgb2
        global bufferlock
        lr = int(np.mean(a[:self.halfwidth,:, 0]))
        lg = int(np.mean(a[:self.halfwidth,:, 1]))
        lb = int(np.mean(a[:self.halfwidth,:, 2]))

        rr = int(np.mean(a[self.halfwidth:,:, 0]))
        rg = int(np.mean(a[self.halfwidth:,:, 1]))
        rb = int(np.mean(a[self.halfwidth:,:, 2]))

        bufferlock.acquire()
        rgb1 = bytearray([lr,0,lg,0,lb,0])
        rgb2 = bytearray([rr,0,rg,0,rb,0])
        bufferlock.release()
        self.frame_num += 1

def picamera_to_buffer():
    global camera
    with picamera.PiCamera() as camera:
        camera.resolution = (320, 240)
        camera.framerate = 30

        camera.zoom = (0.36, 0.52, 0.19, 0.19)
        camera.vflip = True
        camera.hflip = True
        with MyAnalysis(camera) as output:
            camera.start_recording(output, 'rgb')
            camera.wait_recording(86400)
            

try:
    try:
        threads = list()

        if commandlineargs.random:
            verbose("Starting randomizer")
            t = threading.Thread(target=random_to_buffer)
            t.start()
            threads.append(t)
        elif commandlineargs.picamera:
            verbose("Starting picamera")
            t = threading.Thread(target=picamera_to_buffer)
            t.start()
            threads.append(t)

        if commandlineargs.sendtolight:
            verbose("Starting send to light")
            cmd = ["openssl","s_client","-dtls1_2","-cipher","DHE-PSK-AES256-GCM-SHA384","-psk_identity",clientdata['username'],"-psk",clientdata['clientkey'], "-connect", hueip+":2100"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=False)
            t = threading.Thread(target=buffer_to_light, args=(proc,))
            t.start()
            threads.append(t)



        input("Press return to stop")
        stopped=True
        if isinstance(camera,picamera.PiCamera):
            if camera.recording:
                camera.stop_recording()
        
        for t in threads:
            t.join()
    except Exception as e:
        print(e)
        stopped=True

    # input("Press Enter to continue...")
finally:
    verbose("Disabling streaming on group")
    r = requests.put(url = baseurl+"{}/groups/{}".format(clientdata['username'],groupid),json={"stream":{"active":False}}) 
    jsondata = r.json()
    verbose(jsondata)