import glob
import socket
import time
import struct
import sys
import os

def checksum(msg):
    if len(msg) % 2 != 0:
        msg += struct.pack('!B', 0)

    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s = s + w

    s = (s>>16) + (s & 0xffff);
    #s = s + (s >> 16);
    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def calculate_checksum(source_ip, dest_ip, tcp_header, tcp_data):
    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(source_ip),
        socket.inet_aton(dest_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(tcp_data))

    return checksum(pseudo_header + tcp_header + tcp_data)

def modify_seed(new_syn_seq_num, new_synack_seq_num, file_name, source_ip, dest_ip):
    # Open the file and read its contents
    with open(file_name, 'rb') as f:
        file_data = f.read()

    # Extract old sequence numbers from the file
    old_syn_seq_num, old_synack_seq_num = struct.unpack('!II', file_data[:8])  # '!II' means two unsigned integers in network byte order

    # Remove the first 8 bytes from the file data and split it by CRLF
    packets = file_data[8:].split(b'\r\n')

    # Calculate relative sequence and acknowledgment numbers for each packet
    for i in range(len(packets) - 1):  # exclude last empty packet after final split
        packet = packets[i]
        # sequence and acknowledgment numbers are located at 4-8 and 8-12 bytes of TCP header
        seq_num, ack_num = struct.unpack('!II', packet[4:12])
        relative_seq_num = seq_num - old_syn_seq_num
        relative_ack_num = ack_num - old_synack_seq_num
        print(relative_seq_num, relative_ack_num)

        # Calculate new sequence and acknowledgment numbers
        new_seq_num = new_syn_seq_num + relative_seq_num
        new_ack_num = new_synack_seq_num + relative_ack_num

        # Replace the sequence and acknowledgment numbers in the packet
        packets[i] = packet[:4] + struct.pack('!II', new_seq_num, new_ack_num) + packet[12:]

    for i in range(len(packets) - 1):  # exclude last empty packet after final split
        # Recalculate the checksum
        tcp_header = packets[i][:20]
        tcp_data = packets[i][20:]
        tcp_data += b'\r\n'
        # Make checksum field in TCP header zero
        tcp_header = tcp_header[:16] + struct.pack('!H', 0) + tcp_header[18:]

        checksum = calculate_checksum(source_ip, dest_ip, tcp_header, tcp_data)

        # Insert the new checksum into the TCP header
        packets[i] = tcp_header[:16] + struct.pack('!H', checksum) + tcp_header[18:] + tcp_data
        print("new checksum is ", checksum)

    # Join the packets back together and write the result to the file
    with open(file_name, 'wb') as f:
        for packet in packets:
            f.write(packet)

# Verify command line arguments
if len(sys.argv) != 5:
    print("Usage: python script.py <client_ip> <server_ip> <client_seq_num> <server_seq_num>")
    sys.exit(1)

client_ip = sys.argv[1]
server_ip = sys.argv[2]
syn_seq_num = int(sys.argv[3])
synack_seq_num = int(sys.argv[4])

for path in glob.glob("lightftpd/*.raw"):
    modify_seed(syn_seq_num, synack_seq_num, path, client_ip, server_ip)

