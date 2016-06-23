import os
import re
import sys
import socket
import struct
import argparse
import threading
from queue import Queue
from select import select


def is_user_admin():
    if os.name == 'nt':
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            traceback.print_exc()
            return False
    elif os.name == 'posix':
        return os.getuid() == 0
    else:
        raise RuntimeError("Unsupported operating system: %s" % (os.name,))


# PROTO CHECKER
#
def get_resp(host, port, tcp, message=None):
    try:
        if tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            if message is not None:
                sock.send(message)
            data = sock.recv(4096)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if message is not None:
                sock.sendto(message, (host, port))
            data, addr = sock.recvfrom(4096)
        return data
    except socket.error as e:
        return None
    finally:
        sock.close()


def check_ntp(host, port, tcp):
    message = struct.pack(
        '>BBBBII4sQQQQ',
        (0 << 6) | (4 << 3) | 3,
        16, 0, 0, 0, 0,
        b'\x00',
        0, 0, 0, 0
    )

    data = get_resp(host, port, tcp, message)

    if data is None:
        return False

    try:
        data = struct.unpack('>BBBBII4sQQQQ', data)
        return True
    except struct.error as e:
        return False


def check_dns(host, port, tcp):
    message = b'\x00\x0f\x01\x00\x00\x01'\
              b'\x00\x00\x00\x00\x00\x00'\
              b'\x02vk\x03com\x00\x00\x01\x00\x01'
    
    data = get_resp(host, port, tcp, message)

    if data is None:
        return False
    
    try:
        data = struct.unpack('!H2B4H', data[:12])
        return True
    except struct.error as e:
        return False


def check_smtp(host, port, tcp):
    data = get_resp(host, port, tcp)

    if data is None:
        return False

    if re.search(br'220', data):
        return True

    return False


def check_pop3(host, port, tcp):
    data = get_resp(host, port, tcp)

    if data is None:
        return False

    if re.search(br'OK', data):
        return True

    return False


def check_http(host, port, tcp):
    message = b'GET www.google.com HTTP/1.1\r\n\r\n'

    data = get_resp(host, port, tcp, message)

    if data is None:
        return False

    if re.search(br'HTTP', data):
        return True

    return False


proto_checkers = {
    'NTP': check_ntp,
    'DNS': check_dns,
    'SMTP': check_smtp,
    'POP3': check_pop3,
    'HTTP': check_http,
}


def check_proto(host, port, tcp):
    for proto in proto_checkers:
        if proto_checkers[proto](host, port, tcp):
            return proto
    return 'Unknown proto'


# SCANNER
#
def scan_tcp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
            print("%d/tcp = + (%s)" % (port, check_proto(host, port, True)))
            tcp_ports.append(port)
        except socket.error:
            print("%d/tcp = -" % port)
            pass


def scan_udp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.sendto(b'', (host, port))
            sock.recv(1024)
            print("%d/udp = + (%s)" % (port, check_proto(host, port, False)))
            udp_ports.append(port)
        except socket.error as e:
            proto = check_proto(host, port, False)
            if proto != 'Unknown proto':
                print("%d/udp = + (%s)" % (port, proto))
                udp_ports.append(port)
            else:
                print("%d/udp = ?" % port)
                maybe_ports.append(port)


def get_from_sniffer():
    while select([sniffer], [], [], TIMEOUT)[0]:
        data = sniffer.recv(1024)
        icmp_header = data[20:52]
        res_port = icmp_header[-2:]
        icmp_header = icmp_header[:2]
        port = struct.unpack('!h', res_port)[0]
        if icmp_header == b'\x03\x03':
            print("%d/udp = -" % port)
        else:
            print("%d/udp = +" % port)
            udp_ports.append(port)
        maybe_ports.remove(port)


def scan(host, ports, workers_count=100):
    ports_count = len(ports)
    q = Queue()

    def threader():
        while True:
            port = q.get()
            scan_tcp(host, port)
            scan_udp(host, port)
            q.task_done()

    for port in ports:
        q.put(port)

    for i in range(workers_count):
        t = threading.Thread(target=threader, daemon=True)
        t.start()

    q.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--ports', default='1-512',
                        help='Ports we will scan. Example: 1-3,2-10,52,522')
    parser.add_argument('address', type=str)

    args = parser.parse_args()

    try:
        host = socket.gethostbyname(args.address)
    except socket.gaierror:
        print("Hostname %s doesn't exist" % host)
        return

    print('Scanning %s' % host)

    if args.ports == '-': args.ports = '1-65535'
    ranges = (x.split("-") for x in args.ports.split(","))
    ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]

    scan(host, ports)

    tcp_ports.sort()
    udp_ports.sort()

    print("\nOpened TCP ports (%i):\n%s" % (len(tcp_ports), tcp_ports))
    print("\nOpened UDP ports (%i):\n%s" % (len(udp_ports), udp_ports))


def get_cur_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('google.com', 80))
        return sock.getsockname()[0]


if __name__ == '__main__':
    if not is_user_admin():
        print('Please run the program as Administrator')
        sys.exit()

    TIMEOUT = 2

    socket.setdefaulttimeout(TIMEOUT)

    cur_ip = get_cur_ip()

    tcp_ports = []
    udp_ports = []
    maybe_ports = []

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sniffer:
        sniffer.bind((cur_ip, 0))
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        main()
