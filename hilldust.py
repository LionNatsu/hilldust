#!/usr/bin/env python

import sys
#if sys.version_info.major == 2:
#    exec('print "This program cannot be run in Python 2."')
#    exit(1)

if len(sys.argv) != 4:
    print('Usage:', sys.argv[0], 'ADDRESS:PORT', 'USERNAME', 'PASSWORD')
    exit(2)

import os
if os.getuid() != 0:
    print('Need to be root.')
    exit(3)

target = sys.argv[1]
delim_index = target.rindex(':')
host, port = target[:delim_index], target[delim_index+1:]

import impl_scapy
c = impl_scapy.Client()
c.connect(host, int(port))
print('Connected.')
c.auth(sys.argv[2], sys.argv[3], '', '')
print('Authentication completed.')
c.client_info()
c.wait_network()
print('Got network configuration.')
c.new_key()
print('Key exchanging completed.')

import platform_linux
platform_linux.set_network(c)
print('Network configured.')

def inbound_handle():
    while True:
        raw = c.recv()
        platform_linux.write(raw)

def outbound_handle():
    while True:
        raw = platform_linux.read()
        c.send(raw)

from threading import Thread
Thread(target=inbound_handle, daemon=True).start()
Thread(target=outbound_handle, daemon=True).start()

try:
    input('Enter to exit.')
except KeyboardInterrupt:
    pass

print('Logout.')
c.logout()
platform_linux.restore_network(c)
print('Network restored.')
