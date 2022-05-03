from cProfile import label
import socket
import click
import matplotlib.pyplot as plt
from struct import *
import struct
import select
import time
import json, os
import binascii
from getkey import getkey


class bcol:
    SERVER_col = "\033[95m"  # LightMagenta
    CLIENT_col = "\033[94m"  # LightYellow
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"  # LigntRed
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def clean() -> None:
    os.system("cls" if os.name == "nt" else "clear")


class Firewall:
    def __init__(self, interface1, interface2, dos_threshold=0):

        self.internal_socket, self.external_socket = self.initialize_socket(interface1, interface2)

        self.rules_set = {}
        self.mapping_dict = self.load_mapper("mapper.json")
        self.packet = ""
        self.times = []

        self.dos_threshold = dos_threshold
        self.sources_ipv4 = {}

        self.mean_time = 0.0
        self.plot_allow, self.plot_discard = [], []
        self.allowed, self.discarded = 0, 0

    def load_mapper(self, mapper_file):
        with open(mapper_file, "r") as handler:
            mapper = json.load(handler)
        return mapper

    def initialize_socket(self, interface1, interface2):
        internal_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x003))
        external_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        internal_socket.bind((interface1, 0))
        external_socket.bind((interface2, 0))

        return internal_socket, external_socket

    def parse_L2(self, raw_data, byte_len=14):
        self.packet = f"{bcol.OKBLUE}[Ethernet]{bcol.ENDC}"

        dest, src, prototype = struct.unpack("!6s6sH", raw_data[:byte_len])
        dstn_mac = ":".join("%02x" % m for m in dest)
        src_mac = ":".join("%02x" % s for s in src)

        eproto = socket.htons(prototype)

        self.mapping_dict["dstn_mac"] = dstn_mac
        self.mapping_dict["src_mac"] = src_mac
        self.mapping_dict["etherprotocol"] = eproto
        if eproto == socket.ntohs(0x0800):
            self.parse_IP_headers(raw_data[14:])

    def parse_L3(self, raw_data):
        self.packet += f"{bcol.OKBLUE}[IPv4]{bcol.ENDC}"

        iph = unpack("!BBHHHBBH4s4s", raw_data[:20])

        version_len = iph[0]

        ihl = version_len & 0xF
        ihl_len = ihl * 4

        ipv4protocol = iph[6]

        source_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        self.mapping_dict["header_len"] = ihl_len
        self.mapping_dict["ttl"] = iph[5]
        self.mapping_dict["ipv4protocol"] = ipv4protocol
        self.mapping_dict["src_ip"] = source_addr
        self.mapping_dict["dstn_ip"] = dest_addr

        if ipv4protocol == 1:
            self.parse_L3_ICMP(raw_data[ihl_len:])

        elif ipv4protocol == 6:
            self.parse_L3_TCP(raw_data[ihl_len:])

        elif ipv4protocol == 17:
            self.parse_L3_UDP(raw_data[ihl_len:])

    def parseIPv6Head(self, raw_data):
        self.packet += "\u001b[43;1m[IPv6]\u001b[0m"
        iph = struct.unpack("!HHHHHH16s16s", raw_data[:20])

        traffic_class = iph[5]
        flow_label = iph[6]
        header_len = iph[7]
        ipv6protocol = iph[8]
        v6source_addr = ":".join("%0x{0:X2}" % b for b in iph[9])
        v6dest_addr = ":".join("%0x{0:X2}" % b for b in iph[10])

        self.mapping_dict["traffic_class"] = traffic_class
        self.mapping_dict["flow_label"] = flow_label
        self.mapping_dict["ipv4_header_len"] = header_len
        self.mapping_dict["ipv6protocol"] = ipv6protocol
        self.mapping_dict["v6source_addr"] = v6source_addr
        self.mapping_dict["v6dest_addr"] = v6dest_addr

        if ipv6protocol == 1:
            self.parseICMPv6Head(raw_data[header_len:])

        elif ipv6protocol == 6:
            self.parse_L3_TCP(raw_data[header_len:])

        elif ipv6protocol == 17:
            self.parse_L3_UDP(raw_data[header_len:])

    def parse_IP_headers(self, raw_data):
        version_len = raw_data[0]

        version = version_len >> 4

        if version == 4:
            self.parse_L3(raw_data)
        else:
            self.parseIPv6Head(raw_data)

    def parse_L3_ICMP(self, raw_data):
        self.packet += f"{bcol.OKBLUE}[ICMPv4]{bcol.ENDC}"

        typ, code, _, _, _ = struct.unpack("!bbHHh", raw_data[:8])
        self.mapping_dict["icmp4type"] = typ
        self.mapping_dict["icmp4code"] = code

    def parseICMPv6Head(self, raw_data):
        self.packet += "\u001b[44;1mICMPv6\u001b[0m"
        typ, code, _ = struct.unpack("!bbH", raw_data[:4])

        self.mapping_dict["icmp6type"] = typ
        self.mapping_dict["icmp6code"] = code

    def parse_L3_TCP(self, raw_data):
        self.packet += "\u001b[46m;1m[TCP]\u001b[0m"
        (tcpsrc_port, tcpdest_port, _, _, offset) = struct.unpack("!HHLLH", raw_data[:14])
        urg = (offset & 32) >> 5
        ack = (offset & 16) >> 4
        rst = (offset & 4) >> 2
        syn = (offset & 2) >> 1
        fin = offset & 1

        self.mapping_dict["tcpsrc_port"] = tcpsrc_port
        self.mapping_dict["tcpdest_port"] = tcpdest_port

        self.mapping_dict["flag_urg"] = urg
        self.mapping_dict["flag_ack"] = ack
        self.mapping_dict["flag_rst"] = rst
        self.mapping_dict["flag_syn"] = syn
        self.mapping_dict["flag_fin"] = fin

    def parse_L3_UDP(self, raw_data):
        self.packet += "\u001b[47;1m\u001b[30;1m[UDP]\u001b[0m\u001b[0m"
        pack = struct.unpack("!4H", raw_data[:8])
        self.mapping_dict["udpsrc_port"] = pack[0]
        self.mapping_dict["udpdest_port"] = pack[1]
        self.mapping_dict["udpdata_len"] = pack[2]

    def manageRules(self):
        try:
            if os.path.exists("rules.json") == False:
                rules_template = {"L2": [], "L3v4": [], "L3v6": [], "L4TCP": [], "L4UDP": [], "ICMP": []}
                with open("rules.json", "w") as outfile:
                    json.dump(rules_template, outfile)

            os.system("sudo gedit rules.json")

        except KeyboardInterrupt as e:

            self.loadRules()
            clean()
            main()

    def decideRule(self, raw_data):

        start = time.process_time()
        self.parse_L2(raw_data)
        allowed = False

        acceptance = []
        for rulecat in self.rules_set.keys():
            for rule in self.rules_set[rulecat]:
                for key in rule.keys():
                    if key != "rule_id" and key != "rule":
                        if rule[key] == self.mapping_dict[key]:
                            acceptance.append(True)
                        else:
                            acceptance.append(False)
                if all(acceptance) == True:
                    if rule["rule"].lower() == "allow":
                        allowed = True
                    else:
                        allowed = False

        if self.mapping_dict["src_ip"] in self.sources_ipv4:
            self.sources_ipv4[self.mapping_dict["src_ip"]] += 1
        else:
            self.sources_ipv4[self.mapping_dict["src_ip"]] = 0

        if self.sources_ipv4[self.mapping_dict["src_ip"]] > self.dos_threshold:
            print("\u001b[41;1m DoS Detected\u001b[0m")
            allowed = False

        end = time.process_time() - start
        return allowed, end

    def startFirewall(self, internal_MAC, external_MAC):

        clock = time.time()

        while True:
            try:

                all_socks = [self.internal_socket, self.external_socket]
                ready_socks, _, _ = select.select(all_socks, [], [])

                for soc in ready_socks:

                    if time.time() - clock >= 1:
                        self.plot_allow.append(self.allowed)
                        self.plot_discard.append(self.discarded)
                        clock = time.time()

                    raw_data, _ = soc.recvfrom(65565)

                    status, ppt = self.decideRule(raw_data)

                    self.times.append(ppt)
                    self.mean_time = sum(self.times) / len(self.times)

                    if status == True:
                        self.allowed += 1
                        self.discarded += 0

                        if self.mapping_dict["src_mac"] == internal_MAC:

                            dstn_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])
                            dstn_mac = binascii.unhexlify(external_MAC.replace(":", ""))
                            new_data = struct.pack("! 6s 6s H", dstn_mac, src_mac, type_mac) + raw_data[14:]
                            self.external_socket.sendall(new_data)

                        elif self.mapping_dict["src_mac"] == external_MAC:

                            dstn_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])
                            dstn_mac = binascii.unhexlify(internal_MAC.replace(":", ""))
                            new_data = struct.pack("! 6s 6s H", dstn_mac, src_mac, type_mac) + raw_data[14:]
                            self.internal_socket.sendall(new_data)
                        print(
                            f"""{self.packet} \n"""
                            f"""[Src MAC]: {bcol.BOLD}{self.mapping_dict["src_mac"]}{bcol.ENDC}, [Dstn MAC]: {bcol.BOLD}{self.mapping_dict["dstn_mac"]}{bcol.ENDC} \n"""
                            f"""[Src IP]: {bcol.BOLD}{self.mapping_dict["src_ip"]}{bcol.ENDC}, [Dstn IP]: {bcol.BOLD}{self.mapping_dict["dstn_ip"]}{bcol.ENDC} \n"""
                            f"""[Status]: \u001b[42;1mAllowed\u001b[0m \n"""
                            f"""[PPT] : {round(ppt, 8)}\n\n"""
                        )

                    else:
                        self.allowed += 0
                        self.discarded += 1
                        print(
                            f"""{self.packet}\n"""
                            f"""[Src MAC]: {bcol.BOLD}{self.mapping_dict["src_mac"]}{bcol.ENDC}, [Dstn MAC]: {bcol.BOLD}{self.mapping_dict["dstn_mac"]}{bcol.ENDC} \n"""
                            f"""[SrcIP]: {bcol.BOLD}{self.mapping_dict["src_ip"]}{bcol.ENDC}, [Dstn IP]: {bcol.BOLD}{self.mapping_dict["dstn_ip"]}{bcol.ENDC} \n"""
                            f"""[Status]: {bcol.FAIL}{"Dropped"}{bcol.ENDC} \n"""
                            f"""[PPT] : {round(ppt, 8)}\n\n"""
                        )

            except KeyboardInterrupt as e:
                clean()
                self.getStatistics()
                i = True
                print("Press 'c' to continue...")

                while i:
                    key = getkey()
                    if key == "c":
                        i = False
                main()

    def getStatistics(self):

        print("Firewall Capture Statistics\n")
        print("Mean Packet Processing Time : ", self.mean_time, "\n")
        print("No of packets allowed : ", self.allowed, "\n")
        print("No of packets dropped : ", self.discarded, "\n")
        print(f"No of rules in system : {sum(len(v) for v in self.rules_set.values())}")

        plt.title("Firewall Statistics")

        plt.plot(range(len(self.plot_allow)), self.plot_allow, label="Allowed pkts")
        plt.plot(range(len(self.plot_discard)), self.plot_discard, label="Dropped Pkts")

        plt.xlabel("Running Time")
        plt.ylabel("Number of allowed/dropped packets")
        plt.grid()
        plt.legend(["Allowed", "Dropped"])
        plt.savefig("firewall_statistics.png")

    def loadRules(self):
        with open("rules.json", "r") as infile:
            self.rules_set = json.load(infile)

    def set_dos_threshold(self, dos_threshold):
        self.check_dos = True
        self.dos_threshold = dos_threshold


@click.command()
@click.option("-d", help="DDos Attack Detection", default=0)
def main(d):
    # python3 firewall.py True 200
    interface1 = "enp1s0"
    interface2 = "enp6s0"
    firewall = Firewall(interface1, interface2, d)

    clean()
    while True:

        print("\nStart Firewall with 's', Manage Rules with 'r', Exit with 'e' \n\n")

        key = getkey()

        if key == "s":
            try:
                firewall.loadRules()
            except FileNotFoundError:
                pass
            clean()
            firewall.startFirewall(internal_MAC="52:54:00:f7:69:35", external_MAC="52:54:00:d6:10:87")

        if key == "r":
            try:
                firewall.loadRules()
            except FileNotFoundError:
                pass
            firewall.manageRules()

        if key == "e":
            clean()
            exit(0)


if __name__ == "__main__":
    main()
