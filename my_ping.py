import struct
import socket
import argparse
import time


def create_packet(seq_num):
    type = 8
    code = 0
    checksum_placeholder = 0
    identifier = 23  # randomly chosen number
    seq_number = seq_num

    initial_packet = struct.pack('!BBHHH', type, code, checksum_placeholder, identifier, seq_number)

    first_pair_bytes = initial_packet[:2]
    second_pair_bytes = initial_packet[2:4]
    third_pair_bytes = initial_packet[4:6]
    fourth_pair_bytes = initial_packet[6:]

    calculated_checksum = bin(int.from_bytes(first_pair_bytes, byteorder='big', signed=False)
                           + int.from_bytes(second_pair_bytes, byteorder='big', signed=False)
                           + int.from_bytes(third_pair_bytes, byteorder='big', signed=False)
                           + int.from_bytes(fourth_pair_bytes, byteorder='big', signed=False))

    complemented_checksum = (~int(calculated_checksum, 2) & 0xFFFF)
    # complemented_checksum = bin(0xFFFF - int(calculated_checksum, 2))

    return struct.pack('!BBHHH', type, code, complemented_checksum, identifier, seq_number)

def send_packet(packet, address):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        raw_socket.sendto(packet, (address, 1))
    except PermissionError:
        print("You need admin")
    finally:
        raw_socket.close()

def recieve_packet():
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.bind(('0.0.0.0', 0))
    packet, addr = raw_socket.recvfrom(65565)
    print(f"Received packet from {addr}: {packet}")
    raw_socket.close()

def main():
    # Define command line parameters.
    parser = argparse.ArgumentParser(prog='my_ping', description='Sends and receives ICMP echo packets')
    parser.add_argument('address')
    parser.add_argument('-c', action='store')
    parser.add_argument('-i', action='store')
    parser.add_argument('-s', action='store_true')
    parser.add_argument('-t', action='store_true')

    args = parser.parse_args()

    iteration = 0
    while True:
        packet = create_packet(iteration)

        send_packet(packet, args.address)

        recieve_packet()

        iteration += 1
        if args.c is not None and iteration >= int(args.c):
            break

        time_to_sleep = 1 if args.i is None else int(args.i)
        time.sleep(time_to_sleep)

if __name__ == '__main__':
    main()