#!/bin/python3
import scapy.all
import hillstone

class Client(hillstone.ClientCore):
    def __init__(self):
        super().__init__()
        self.outbound_sa = None
        self.inbound_sa = None

    def new_key(self):
        super().new_key()
        self.outbound_sa = scapy.all.SecurityAssociation(
            proto=scapy.all.ESP,
            spi=self.ipsec_param.out_spi,
            crypt_algo='3DES',
            crypt_key=self.ipsec_param.out_crypt_key,
            auth_algo='HMAC-SHA1-96',
            auth_key=self.ipsec_param.out_auth_key
        )
        self.inbound_sa = scapy.all.SecurityAssociation(
            proto=scapy.all.ESP,
            spi=self.ipsec_param.in_spi,
            crypt_algo='3DES',
            crypt_key=self.ipsec_param.in_crypt_key,
            auth_algo='HMAC-SHA1-96',
            auth_key=self.ipsec_param.in_auth_key
        )

    def encap(self, datagram:bytes):
        raw = scapy.all.raw(scapy.all.IP() / scapy.all.IP(datagram))
        return self.outbound_sa.encrypt(scapy.all.IP(raw), iv=self.ipsec_param.out_iv).payload

    def decap(self, datagram:bytes):
        raw = scapy.all.raw(scapy.all.IP() / scapy.all.ESP(datagram))
        return self.inbound_sa.decrypt(scapy.all.IP(raw)).payload


import sys
target = sys.argv[1]
delim_index = target.rindex(':')
host, port = target[:delim_index], target[delim_index+1:]

c = Client()
c.connect(host, int(port))
print('Connected.')
c.auth(sys.argv[2], sys.argv[3], '', '')
print('Authentication completed.')
c.client_info()
c.wait_network()
print('Got network configuration.')
c.new_key()
print('Key exchanging completed.')

import socket
u = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
print('Standby.')

p = open('packet_test.bin', 'rb').read()
u.sendto(bytes(c.encap(p)), (c.server_host, c.server_udp_port))
try:
    d, _ = u.recvfrom(4096)
    c.decap(d).show()
except KeyboardInterrupt:
    pass

print('Logout.')
c.logout()
