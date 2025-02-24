"""Implement ping functionality"""
import struct
import socket
import argparse
import time
from multiprocessing import Process
import numpy as np


def create_packet(seq_num, payload_size):
    """
    create an ICMP packet for ping

    :param seq_num: the sequence number of the packet
    :param payload_size: size of the packet's payload
    :return: the ICMP packet
    """
    type = 8
    code = 0
    checksum_placeholder = 0
    identifier = 23  # randomly chosen number
    seq_number = seq_num
    payload = bytes(payload_size)
    if len(payload) % 2 == 1:
        payload += b'\x00'  # if payload is odd length of bytes, pad
        # so it can be used for checksum

    initial_packet = struct.pack('!BBHHH', type, code, checksum_placeholder,
                                 identifier, seq_number)
    packet_with_payload = initial_packet + payload

    # Calculate the packet's checksum
    checksum = 0
    for index in range(0, len(packet_with_payload), 2):
        checksum += ((packet_with_payload[index] << 8)
                     + packet_with_payload[index + 1])
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF

    return (packet_with_payload[:2] + struct.pack('!H', checksum)
            + packet_with_payload[4:])

def send_packet(packet, address):
    """
    send a packet using a raw socket

    :param packet: the packet to send
    :param address: IP address to send the packet to
    """
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                               socket.IPPROTO_ICMP)
    try:
        raw_socket.sendto(packet, (address, 1))
    finally:
        raw_socket.close()

def recieve_packet(start_time):
    """
    attempt to receive the reply to the ping ICMP echo request

    :param start_time: time the request packet was sent
    :return: 1 or 0 depending on if the reply was received or not,
    followed by the round trip time of the packet
    """
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                               socket.IPPROTO_ICMP)
    raw_socket.bind(('0.0.0.0', 0))
    raw_socket.settimeout(3)

    rtt = 0
    try:
        packet, addr = raw_socket.recvfrom(65565)
        end_time = time.time()
        rtt = np.round((end_time - start_time) * 1000)
        ttl = int(packet[8])
        print(f"Reply from: {addr[0]}: bytes={len(packet[28:])} time={rtt}ms"
              f" TTL={ttl}")  # bytes = size of payload
    except OSError:
        print("Request Timed Out")
        return 0, rtt
    finally:
        raw_socket.close()

    return 1, rtt

def ping(args):
    """
    send echo requests and measure the number of replies and trip times

    :param args: command line arguments
    """
    payload_size = int(args.s) if args.s is not None else 56
    print(f"Pinging {args.address} with {payload_size} bytes")

    num_pkts_sent = 0
    num_pkts_received = 0
    iteration = 0
    round_trip_times = []
    while True:
        packet = create_packet(iteration, payload_size)

        start_time = time.time()
        send_packet(packet, args.address)
        num_pkts_sent += 1

        pkt_received, rtt = recieve_packet(start_time)
        num_pkts_received += pkt_received
        round_trip_times.append(rtt)

        iteration += 1

        # If -c command line parameter is used, stop ping program after
        # sending and attempting to receive the specified number of
        # packets, and calculate and display statistics regarding the
        # number of packets received or lost and the round trip times
        if args.c is not None and iteration >= int(args.c):
            round_trip_times.sort()
            sum = 0
            for trip_time in round_trip_times:
                sum += trip_time
            average_rtt = sum/len(round_trip_times)

            lost_pkts = num_pkts_sent - num_pkts_received

            print(f"Ping statistics for {args.address}:")
            print(f"    Packets: Sent = {num_pkts_sent}, "
                  f"Received = {num_pkts_received}, "
                  f"Lost = {lost_pkts} "
                  f"({(lost_pkts/num_pkts_sent) * 100}% loss),")
            print("Approximate round trip times in milli-seconds:")
            print(f"    Minimum = {round_trip_times[0]}ms, "
                  f"Maximum = {round_trip_times[-1]}ms, "
                  f"Average = {average_rtt}ms")
            break

        time_to_sleep = 1 if args.i is None else int(args.i)
        time.sleep(time_to_sleep)

def main():
    """parse arguments, call ping(), and terminate ping() after timeout"""
    # Define command line parameters.
    parser = argparse.ArgumentParser(
        prog='my_ping', description='Sends and receives ICMP echo packets')
    parser.add_argument('address')
    parser.add_argument('-c', action='store')
    parser.add_argument('-i', action='store')
    parser.add_argument('-s', action='store')
    parser.add_argument('-t', action='store')

    args = parser.parse_args()

    ping_process = Process(target=ping, args=(args,))
    ping_process.start()
    if args.t is not None:
        ping_process.join(timeout=int(args.t))
        ping_process.terminate()

if __name__ == '__main__':
    main()