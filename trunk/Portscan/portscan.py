import sys
import socket
import argparse
import threading
from queue import Queue


def printProgress (iteration, total, prefix='', decimals=2, barLength=50):
    filledLength = int(round(barLength * iteration / float(total)))
    percents = round(100.00 * (iteration / float(total)), decimals)
    bar = '#' * filledLength + '-' * (barLength - filledLength)
    sys.stdout.write('%s [%s] %s%s\r' % (prefix, bar, percents, '%')),
    sys.stdout.flush()


def get_tcp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
            tcp_ports.append(port)
        except socket.error:
            pass


def get_udp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.sendto(b'', (host, port))
            res, addr = sock.recvfrom(1024)
            udp_ports.append(port)
        except socket.timeout:
            udp_ports.append(port)
        except socket.error:
            pass


def get_by_threads(host, ports, workers_count=100):
    ports_count = len(ports)
    q = Queue()

    def threader():
        while True:
            port = q.get()
            get_tcp(host, port)
            get_udp(host, port)
            printProgress(ports_count - q.qsize(), ports_count, 'Scanned:')
            q.task_done()

    for port in ports:
        q.put(port)

    for i in range(workers_count):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    q.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--ports', default='1-512')
    parser.add_argument('address', type=str)

    args = parser.parse_args()

    host = socket.gethostbyname(args.address)

    if args.ports == '-': args.ports = '1-65535'
    ranges = (x.split("-") for x in args.ports.split(","))
    ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]

    get_by_threads(host, ports)

    tcp_ports.sort()
    udp_ports.sort()

    print("\nOpened TCP ports (%i):\n%s" % (len(tcp_ports), tcp_ports))
    print("\nOpened UDP ports (%i):\n%s" % (len(udp_ports), udp_ports))

if __name__ == '__main__':
    socket.setdefaulttimeout(2)

    tcp_ports = []
    udp_ports = []

    main()
