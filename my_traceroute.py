import struct
import socket
import argparse
import time
from multiprocessing import Process

def get_checksum(data):
    checksum = 0
    for index in range(0, len(data), 2):
        checksum += (data[index] << 8) + data[index + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return ~checksum & 0xFFFF

def create_packet(seq_num, iteration):
    version_ihl = b'\x45'
    type_of_service = 0
    total_length = 28
    identification = b'\xab\xcd'
    flags_frag_offset = 0
    ttl = iteration + 1 # iteration starts at 0, ttl starts at 1
    protocol = 1
    header_checksum = 0
    src_addr = socket.gethostbyname(socket.gethostname())
    dst_addr = socket.gethostbyname("google.com")

    ip_header = (version_ihl + struct.pack('!Bh', type_of_service, total_length) + identification
                 + struct.pack('hBBH', flags_frag_offset, ttl, protocol, header_checksum)
                 + socket.inet_pton(socket.AF_INET, src_addr) + socket.inet_pton(socket.AF_INET, dst_addr))

    ip_checksum = get_checksum(ip_header)

    ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

    type = 8
    code = 0
    checksum_placeholder = 0
    identifier = 23  # randomly chosen number
    seq_number = seq_num

    initial_packet = struct.pack('!BBHHH', type, code, checksum_placeholder, identifier, seq_number)

    icmp_checksum = get_checksum(initial_packet)

    icmp_packet = initial_packet[:2] + struct.pack('!H', icmp_checksum) + initial_packet[4:]

    return ip_header + icmp_packet
    # return icmp_packet

def send_packet(packet, address, ttl):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        raw_socket.sendto(packet, (address, 1))
    finally:
        raw_socket.close()

def recieve_packet():
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.bind(('0.0.0.0', 0))
    packet, addr = raw_socket.recvfrom(65565)
    print(f"Received packet from {addr}: {packet}")
    raw_socket.close()

def trace_route(args):
    iteration = 0
    seq_num = 0
    while True:
        if iteration >= 30:
            break

        for probe in range(3):
            packet = create_packet(seq_num, iteration)
            send_packet(packet, args.address, iteration)
            # recieve_packet()
            seq_num += 1

        iteration += 1

def main():
    # Define command line parameters.
    parser = argparse.ArgumentParser(prog='my_traceroute', description='Sends and receives ICMP echo packets')
    parser.add_argument('address')
    parser.add_argument('-n', action='store_true')
    parser.add_argument('-q', action='store')
    parser.add_argument('-S', action='store_true')

    args = parser.parse_args()

    trace_route(args)

if __name__ == '__main__':
    main()