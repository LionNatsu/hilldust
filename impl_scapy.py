import hillstone
import scapy.all

class Client(hillstone.ClientCore):
    def __init__(self):
        super(Client, self).__init__()
        import socket
        self.outbound_sa = None
        self.inbound_sa = None
        self.udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    def new_key(self):
        super(Client, self).new_key()
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

    def _encap(self, datagram):
        raw = scapy.all.raw(scapy.all.IP() / scapy.all.IP(datagram))
        return self.outbound_sa.encrypt(scapy.all.IP(raw), iv=self.ipsec_param.out_iv).payload

    def _decap(self, datagram):
        raw = scapy.all.raw(scapy.all.IP() / scapy.all.ESP(datagram))
        return self.inbound_sa.decrypt(scapy.all.IP(raw)).payload

    def recv(self):
        d, _ = self.udp_socket.recvfrom(8192)
        return bytes(self._decap(d))

    def send(self, datagram):
        print(datagram, self.server_host, self.server_udp_port)
        return self.udp_socket.sendto(bytes(self._encap(datagram)), (self.server_host, self.server_udp_port))

