from curses import raw
import socket
import sys
import json
from struct import *
import struct
import select
import pyfiglet
import binascii


def load_rules(filename="rules.json"):
    fd = open(filename, "r")
    data = json.load(fd)
    fd.close()
    return data


class SimpleFirewall:
    def __init__(self, interface1, interface2):
        self.host1sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.extsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        self.host1sock.bind((interface1, 0))
        self.extsock.bind((interface2, 0))

        self.rules = load_rules("simple_rules.json")

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

            if ip[4] in self.rules["BLOCKED_IP_LIST"]:
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


class AdvancedFirewall:
    def __init__(self, interface1, interface2):
        self.host1sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x003))
        self.extsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        self.host1sock.bind((interface1, 0))
        self.extsock.bind((interface2, 0))

        self.internal_host = {"ip": "192.68.135.135", "mac": "52:54:00:f7:69:35"}

        self.all_rules = {
            "Ether_rules": {"src": [], "dstn": []},
            "IPv4rules": {"src": [], "dstn": []},
            "IPv6rules": [],
            "TCPrules": [],
            "UDPrules": [],
            "ICMPrules": [],
        }

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

        rules = load_rules()

        print(eth[1])

        if eth[1] == "52:54:00:f7:69:35":
            allow = True
            packet_type = "Internal"

            dest_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])

            dest_mac = binascii.unhexlify("52:54:00:d6:10:87".replace(":", ""))

            new_data = struct.pack("! 6s 6s H", dest_mac, src_mac, type_mac)
            new_data = new_data + raw_data[14:]

            self.extsock.sendall(new_data)

        elif eth[1] in rules["Ether_rules"]["src"]:
            allow = False
            packet_type = "External"

        elif ip[4] in rules["IPv4rules"]["src"]:
            allow = False
            packet_type = "External"

        else:
            allow = True
            packet_type = "External"
            dest_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])

            dest_mac = binascii.unhexlify(self.internal_host["mac"].replace(":", ""))

            new_data = struct.pack("! 6s 6s H", dest_mac, src_mac, type_mac)

            new_data = new_data + raw_data[14:]

            self.host1sock.sendall(new_data)

        return allow, packet_type

    def manageRule(self):
        print("1.ADD RULE\n")
        opt = int(input("Enter Your Option\n"))
        if opt == 1:

            print("Choose Type of Rule\n")
            print("1.Ethernet (Layer 2)\n")
            print("2.IPV4 Rule (layer 3)\n")
            rule_opt = int(input("Enter Your Option\n"))

            if rule_opt == 1:
                print("\u001b[33;1mEthernet Rule\n")
                if input("Want to match Source MAC? (y/n)") == "y":
                    src_mac = input("\u001b[33;1mEnter Source MAC : \u001b[0m")
                    self.all_rules["Ether_rules"]["src"].append(src_mac)

            if rule_opt == 2:
                print("\u001b[33;1mIPv4 Rule\u001b[0m\n")
                if input("Want to match Source IP? (y/n)") == "y":
                    src_ip = input("\u001b[33;1mEnter Source IP : \u001b[0m")
                    self.all_rules["IPv4rules"]["src"].append(src_ip)

            with open("rules.json", "w") as fp:
                json.dump(self.all_rules, fp)

    def startFirewall(self):

        self.manageRule()

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
            banner = pyfiglet.figlet_format("Simple Firewall", "standard")
            print(banner)
            print("\u001b[33;1m1.Start Firewall\u001b[0m\n")
            option = int(input("Enter Your Choice:\n"))
            if option == 1:
                sf = SimpleFirewall(interface1, interface2)
                sf.startFirewall()
            else:
                exit(0)
        elif firewall_opt == "advanced_firewall":
            # banner = pyfiglet.figlet_format("Advanced Firewall", "standard")
            # print(banner)
            af = AdvancedFirewall(interface1, interface2)
            af.startFirewall()
