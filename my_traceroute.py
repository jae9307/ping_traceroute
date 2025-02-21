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
    type = 8
    code = 0
    checksum_placeholder = 0
    identifier = 23  # randomly chosen number
    seq_number = seq_num

    initial_packet = struct.pack('!BBHHH', type, code, checksum_placeholder, identifier, seq_number)

    icmp_checksum = get_checksum(initial_packet)

    icmp_packet = initial_packet[:2] + struct.pack('!H', icmp_checksum) + initial_packet[4:]

    return icmp_packet

def send_packet(packet, address, ttl):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    try:
        raw_socket.sendto(packet, (address, 1))
    finally:
        raw_socket.close()

def recieve_packet(start_time, probe):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.bind(('0.0.0.0', 0))
    raw_socket.settimeout(5)
    try:
        packet, addr = raw_socket.recvfrom(65565)
        end_time = time.time()
        time_elapsed = (end_time - start_time) * 1000
        print(f"{time_elapsed} ms", end ="    ")
        if probe == 2:
            print(addr[0])
    except OSError:
        return None
    finally:
        raw_socket.close()

def trace_route(args):
    iteration = 1
    seq_num = 0
    while True:
        if iteration > 30:
            break

        print(iteration, end ="    ")

        for probe in range(3):
            packet = create_packet(seq_num, iteration)
            start_time = time.time()
            send_packet(packet, args.address, iteration)
            seq_num += 1
            recieve_packet(start_time, probe)

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