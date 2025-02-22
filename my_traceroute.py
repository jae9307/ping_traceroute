import struct
import socket
import argparse
import time
import numpy as np

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
    raw_socket.settimeout(3)

    address = ''
    try:
        packet, reply_address = raw_socket.recvfrom(65565)
        end_time = time.time()
        time_elapsed = (end_time - start_time) * 1000
        print(f"{np.round(time_elapsed)} ms", end ="    ")
        if reply_address is not None:
            address = reply_address[0]
    except OSError:
        print("*", end="         ")
        return None
    finally:
        raw_socket.close()

    return address

def trace_route(args):
    num_probes = int(args.q) if args.q is not None else 3

    iteration = 1
    seq_num = 0
    num_unanswered_probes = 0
    while True:
        if iteration > 30:
            break

        print(iteration, end ="    ")

        address = 'Request Timed Out'
        for probe in range(num_probes):
            packet = create_packet(seq_num, iteration)
            start_time = time.time()
            send_packet(packet, args.address, iteration)
            seq_num += 1
            reply_address = recieve_packet(start_time, probe)
            if reply_address is not None:
                address = reply_address
            else:
                num_unanswered_probes += 1

        if args.n is False:
            try:
                hostname = socket.gethostbyaddr(address)
                print(f'{hostname[0]} [{address}]')
            except (socket.herror, socket.gaierror):
                print(address)
        else:
            print(address)

        if address == args.address:
            break

        iteration += 1

    if args.S is True:
        print(f'Number of unanswered probes: {num_unanswered_probes}')

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