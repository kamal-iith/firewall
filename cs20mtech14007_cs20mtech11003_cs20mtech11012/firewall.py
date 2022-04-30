from curses import raw
import socket
import sys
from os import system
from struct import *
import struct
import select
import pyfiglet
import binascii


BLOCKED_IP_LIST = ["142.250.182.46"]


class SimpleFirewall:
    def __init__(self, interface1, interface2):
        self.host1sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.extsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        self.host1sock.bind((interface1, 0))
        self.extsock.bind((interface2, 0))

    def get_ip(self, addr):
        return ".".join(map(str, addr))

    def parseEtherHead(self, raw_data):
        dest, src, prototype = struct.unpack("!6s6sH", raw_data[:14])
        destin_mac_addr = ":".join("%02x" % b for b in dest)
        src_mac_addr = ":".join("%02x" % b for b in src)
        prototype_field = socket.htons(prototype)
        return destin_mac_addr, src_mac_addr, prototype_field

    def parseIPHead(self, raw_data):
        version_header_length = raw_data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
        data = raw_data[header_length:]
        src = self.get_ip(src)
        target = self.get_ip(target)
        return version, header_length, ttl, proto, src, target, data

    def decideRule(self, raw_data):

        eth = self.parseEtherHead(raw_data)  # destin_mac_addr, src_mac_addr, prototype_field

        ip = self.parseIPHead(raw_data[14:])

        # eth[1] = Source MAC address
        if eth[1] == "52:54:00:d6:10:87":  # Rule1 : Allow IP from external host

            print(ip[4])

            if ip[4] in BLOCKED_IP_LIST:
                allow = False
                packet_type = "External"
            else:
                allow = True
                packet_type = "External"
                dest_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])

                dest_mac = binascii.unhexlify("52:54:00:f7:69:35".replace(":", ""))

                new_data = struct.pack("! 6s 6s H", dest_mac, src_mac, type_mac)

                new_data = new_data + raw_data[14:]

                self.host1sock.sendall(new_data)

        elif eth[1] == "52:54:00:f7:69:35":  # Rule2 : Allow Host1 Packets from host1
            allow = True
            packet_type = "Internal"

            dest_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])

            dest_mac = binascii.unhexlify("52:54:00:d6:10:87".replace(":", ""))

            new_data = struct.pack("! 6s 6s H", dest_mac, src_mac, type_mac)
            new_data = new_data + raw_data[14:]

            self.extsock.sendall(new_data)

        else:  # Rule 5: Disallow all external packets
            allow = False
            packet_type = "External"

        return allow, packet_type

    def startFirewall(self):
        # print("\u001b[41;1m\t\tSimple Firewall Running...\u001b[0m\n")

        while True:
            all_socks = [self.host1sock, self.extsock]

            ready_socks, _, _ = select.select(all_socks, [], [])

            for soc in ready_socks:
                raw_data, addr = soc.recvfrom(65565)
                ret = self.decideRule(raw_data)

                if ret[0]:
                    print("Packet \u001b[42;1m Allowed\u001b[0m\t Packet Type: ", ret[1])
                else:
                    print("Packet \u001b[41;1m Discarded\u001b[0m\t Packet Type: ", ret[1])


if __name__ == "__main__":
    firewall_opt = sys.argv[1]
    interface1 = sys.argv[2]  # enp1s0
    interface2 = sys.argv[3]  # enps60

    while True:
        if firewall_opt == "simple_firewall":
            # banner = pyfiglet.figlet_format("SIMPLE FIREWALL", "standard")
            # print(banner)

            # print("\u001b[33;1m1.Start Firewall\u001b[0m\n")
            # print("\u001b[33;1m2.Print Firewall description\u001b[0m\n")
            # print("\u001b[33;1m3.Exit\u001b[0m\n")
            # option = int(input("Enter Your Choice:\n"))
            # if option == 1:
            sf = SimpleFirewall(interface1, interface2)
            sf.startFirewall()

            # elif option == 2:
            #     system("clear")
            #     print("\u001b[36;1m\t\t\tSimple Firewall\u001b[0m\n")
            #     print(
            #         "\u001b[36;1mSimple Firewall represents a simple hardcoded rule based firewall, which works on conditional check on the predefinde hardcoded rule in the program to filter the packets. This Firewall works for only IPV4 packets.\u001b[0m\n"
            #     )
            # elif option == 3:
            #     exit(0)
            # else:
            #     print("Error : Wrong Option\n")
