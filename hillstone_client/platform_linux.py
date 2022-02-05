from . import hillstone

import os
import fcntl
import struct
import subprocess

route_table_bak = b''
nameserver_bak = b''
tun = None

def set_network(c:hillstone.ClientCore):
    global tun, route_table_bak, nameserver_bak
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    tun = open('/dev/net/tun', 'r+b', buffering=0)
    ifr = struct.pack('16sH', b'', IFF_TUN | IFF_NO_PI)
    ifr = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifr = ifr[:ifr.index(b'\0')].decode('ascii')

    subprocess.check_call('ip address add dev '+ifr+' '+str(c.ip_ipv4.ip), shell=True)
    subprocess.check_call('ip link set dev '+ifr+' up', shell=True)
    route_table_bak = subprocess.check_output('ip route save table main', shell=True)
    server_gateway = subprocess.check_output('ip route get fibmatch '+c.server_host, shell=True)
    try:
        server_gateway = server_gateway[server_gateway.index(b' via'):]
    except ValueError:
        server_gateway = server_gateway[server_gateway.index(b' dev'):]
    subprocess.run('ip route add '+c.server_host+server_gateway.decode('ascii'), check=False, shell=True)
    subprocess.check_call('ip route add '+str(c.gateway_ipv4)+' dev '+ifr, shell=True)
    subprocess.check_call('ip route add '+str(c.ip_ipv4.network)+' via '+str(c.gateway_ipv4), shell=True)
    subprocess.check_call('ip route replace default metric 0 via '+str(c.gateway_ipv4), shell=True)
    
    with open('/etc/resolv.conf', 'rb') as f:
        nameserver_bak = f.read()
    
    with open('/etc/resolv.conf', 'wb') as f:
        buf = ''
        for dns in c.dns_ipv4:
            buf += 'nameserver ' + str(dns) + '\n'
        f.write(buf.encode('ascii'))
    
def restore_network(c:hillstone.ClientCore):
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(buffering=0) as f:
        f.write(route_table_bak)
        subprocess.check_call('ip route flush table main', shell=True)
        subprocess.check_call('ip route restore < '+f.name, shell=True, stderr=subprocess.DEVNULL)
    with open('/etc/resolv.conf', 'wb') as f:
        f.write(nameserver_bak)

def write(datagram:bytes):
    os.write(tun.fileno(), datagram)

def read():
    return os.read(tun.fileno(), 8192)
