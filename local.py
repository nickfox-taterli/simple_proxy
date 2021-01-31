import json
import socket
import select
import base64
import requests
from struct import pack, unpack
from threading import Thread, activeCount
from time import sleep
import sys

MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050

VER = b'\x05'
M_NOAUTH = b'\x00'
M_NOTAVAILABLE = b'\xff'
CMD_CONNECT = b'\x01'
ATYP_IPV4 = b'\x01'
ATYP_DOMAINNAME = b'\x03'

SERVER_ENDPOINT = 'http://10.168.1.117/index.php'


def proxy_loop(socket_src, dst):
    while True:
        try:
            reader, _, _ = select.select([socket_src], [], [], 1)
        except select.error:
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_src:
                    print("请求访问 %s:%d" % (dst[0], dst[1]))
                    payload = {'server': dst[0], 'port': dst[1], 'data': base64.b64encode(data).decode('utf-8')}
                    r = requests.post(SERVER_ENDPOINT, data=json.dumps(payload))
                    socket_src.send(r.content)
        except socket.error:
            return


def connect_to_dst(dst_addr, dst_port):
    print(dst_addr)
    print(dst_port)
    sock = create_socket()
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        return 0


def request_client(wrapper):
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        return False
    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else:
        return False
    return (dst_addr, dst_port)


def request(wrapper):
    dst = request_client(wrapper)
    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    rep = b'\x00'
    bnd = socket.inet_aton('127.0.0.1')
    bnd += pack(">H", 61238)
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':
        proxy_loop(wrapper, dst)
    if wrapper != 0:
        wrapper.close()


def subnegotiation_client(wrapper):
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        return False
    return True


def connection(wrapper):
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        sys.exit(0)
    return sock


def bind_port(sock):
    try:
        print('服务器监听端口: %d' % (LOCAL_PORT))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        sock.close()
        sys.exit(0)
    return sock


new_socket = create_socket()
bind_port(new_socket)
while True:
    if activeCount() > MAX_THREADS:
        sleep(3)
        continue
    try:
        wrapper, _ = new_socket.accept()
        wrapper.setblocking(1)
    except socket.timeout:
        continue
    except socket.error:
        continue
    except TypeError:
        sys.exit(0)
    recv_thread = Thread(target=connection, args=(wrapper,))
    recv_thread.start()
new_socket.close()
