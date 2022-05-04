import firewall_utils as utils, json, os, ipaddress, re

class Rules:
    def __init__(self, file_path):
        self.file_path = file_path
        self.int_rules, self.ext_rules, self.int_last_index, self.ext_last_index = utils.load_rules(file_path)
        self.eth_filters = ["ETH", "ARP", "any"]
        self.net_filters = ["IPv4", "IPv6", "ICMP", "any"]
        self.tsp_filters = ["TCP", "UDP", "any"]

    def commit_changes(self):
        with open(self.file_path, 'w', os.O_NONBLOCK) as rule_file:
            json.dump({
                "incoming": self.ext_rules, 
                "outgoing": self.int_rules,
                "incoming_last_index": self.ext_last_index,
                "outgoing_last_index": self.int_last_index
            }, rule_file)
            print("Sucessfully committed changes to the rule file, ",self.file_path)
            rule_file.close()

    def input_rule(self):
        rule_eth = input("Enter Link Layer protocol filter for the rule [ETH/ARP/any]: ")
        while rule_eth not in self.eth_filters:
            rule_eth = input("Invalid Link Layer protocol filter! Please try again [ETH/ARP/any]: ")
        rule_net = input("Enter Network Layer protocol filter for the rule [IPv4/IPv6/ICMP/any]: ")
        while rule_net not in self.net_filters:
            rule_net = input("Invalid Network Layer filter! Please try again [IPv4/IPv6/ICMP/any]: ")
        rule_tsp = input("Enter Transport Layer protocol filter for the rule [TCP/UDP/any]: ")
        while rule_tsp not in self.tsp_filters:
            rule_tsp = input("Invalid Transport Layer protocol filter! Please try again [TCP/UDP/any]: ")
        rule_src_ip = input("Enter source ip address (or subnet mask) filter [eg. 10.0.0.1 or 10.0.0.1/24 or any]: ")
        while not (rule_src_ip == "any" or self.check_ip(rule_src_ip)):
            rule_src_ip = input("Invalid ip address (or subnet mask)! Please try again: ")
        rule_dst_ip = input("Enter destination ip address (or subnet mask) filter [eg. 10.0.0.1 or 10.0.0.1/24 or any]: ")
        while not (rule_dst_ip == "any" or self.check_ip(rule_dst_ip)):
            rule_dst_ip = input("Invalid ip address (or subnet mask)! Please try again: ")
        rule_src_port = input("Enter source port (or port range) filter [eg. 50 or 45-53 or any]: ")
        while not (rule_src_port == "any" or self.check_port(rule_src_port)):
            rule_src_port = input("Invalid port (or port range)! Please try again:")
        rule_dst_port = input("Enter destination port (or port range) filter [eg. 50 or 45-53 or any]: ")
        while not (rule_dst_port == "any" or self.check_port(rule_dst_port)):
            rule_dst_port = input("Invalid port (or port range)! Please try again: ")
        rule_src_mac = input("Enter source MAC filter: ")
        while not (rule_src_mac == "any" or self.check_mac(rule_src_mac)):
            rule_src_mac = input("Invalid MAC address! Please try again: ")
        new_rule = {
            utils.ETH_PROTO : rule_eth,
            utils.NET_PROTO : rule_net,
            utils.TSP_PROTO : rule_tsp,
            utils.SRC_IP : rule_src_ip,
            utils.DST_IP : rule_dst_ip,
            utils.SRC_PORT : rule_src_port,
            utils.DST_PORT : rule_dst_port,
            utils.SRC_MAC : rule_src_mac
        }
        return new_rule

    def add(self):
        print("")
        print("Please enter the relevent filters for the rule:")
        new_rule = self.input_rule()
        rule_set = input("Add the rule to internal network rules or external network rules? [i/e]: ")
        while rule_set != "i" and rule_set != "e":
            rule_set = input("Invalid response! Please try again: ")
        if rule_set == "e":
            new_rule["index"] = self.ext_last_index + 1
            self.ext_last_index += 1
            self.ext_rules.append(new_rule)
        else:
            new_rule["index"] = self.int_last_index + 1
            self.int_last_index += 1
            self.int_rules.append(new_rule)
        self.commit_changes()

    def get_rule_from_index(self, rules, index):
        for idx, rule in enumerate(rules):
            if rule["index"] == index:
                return idx
        return None

    def edit_rule(self, rule_set, index):
        print("")
        if rule_set == "-e":
            rules = self.ext_rules
        else:
            rules = self.int_rules
        rule_num = self.get_rule_from_index(rules, index)
        if rule_num == None:
            print("Invalid index! Please try again!")
        else:
            print("Displaying the rule to be edited:")
            print("-"*80)
            self.print_rule(rules[rule_num])
            print("-"*80)
            print("")
            print("Now provide alternate filters for the above rule:")
            new_rule = self.input_rule()
            print("")
            confirmation = input("Confirm update to the above rule? [Y/N]: ")
            if confirmation == "Y":
                new_rule["index"] = index
                rules[rule_num] = new_rule
                if rule_set == "-e":
                    self.ext_rules = rules
                else:
                    self.int_rules = rules
                self.commit_changes()
            else:
                print("Updation cancelled!")

    def check_mac(self, mac):
        regex = ("^([0-9A-Fa-f]{2}[:-])" + "{5}([0-9A-Fa-f]{2})|" +
                "([0-9a-fA-F]{4}\\." + "[0-9a-fA-F]{4}\\." +
                "[0-9a-fA-F]{4})$")  
        p = re.compile(regex)
        if re.search(p, mac):
            return True
        else:
            return False

    def check_ip(self, ip):
        try:
            ipaddress.ip_network(ip)
            return True
        except ValueError:
            return False
    
    def check_port(self, port):
        if "-" in port:
            [start_port, stop_port] = port.split("-")
            if not start_port.isnumeric() or not stop_port.isnumeric():
                return False
        else:
            return port.isnumeric()
        return True

    def print_rule(self, rule):
        print("RULE INDEX: ",rule["index"])
        print("LINK LAYER: ", rule[utils.ETH_PROTO], ", NETWORK LAYER: ", rule[utils.NET_PROTO], ", TRANSPORT LAYER: ", rule[utils.TSP_PROTO],", SRC MAC: ",rule[utils.SRC_MAC])
        print("SRC IP: ",rule[utils.SRC_IP],", DST IP: ",rule[utils.DST_IP], ", SRC PORT: ",rule[utils.SRC_PORT], ", DST PORT: ",rule[utils.DST_PORT])

    def show_rules(self, rule_set=None, index=None):
        print("")
        if rule_set == None:
            print("-"*20,"RULES FOR PACKETS COMING FROM EXTERNAL NETWORK","-"*20)
            print("="*88)
            if len(self.ext_rules) > 0:
                for idx, rule in enumerate(self.ext_rules):
                    self.print_rule(rule)
                    print("-"*88)
            else:
                print(" "*28,"No rules written here yet!")
            print("="*88)
            print("")
            print("-"*20,"RULES FOR PACKETS GOING FROM INTERNAL NETWORK","-"*20)
            print("="*88)
            if len(self.int_rules) > 0:
                for idx, rule in enumerate(self.int_rules):
                    self.print_rule(rule)
                    print("-"*88)
            else:
                print(" "*28,"No rules written here yet!")
            print("="*88)
        else:
            if rule_set == '-e':
                if index == None:
                    print("-"*20,"RULES FOR PACKETS COMING FROM EXTERNAL NETWORK","-"*20)
                    print("="*88)
                    if len(self.ext_rules) > 0:
                        for idx, rule in enumerate(self.ext_rules):
                            self.print_rule(rule)
                            print("-"*88)
                    else:
                        print(" "*28,"No rules written here yet!")
                    print("="*88)
                else:
                    rule_num = self.get_rule_from_index(self.ext_rules, index)
                    if rule_num == None:
                        print("Invalid rule index for this set of rules! Please Try again!")
                    else:
                        print("-"*20,"RULE INDEX: ",index,", IN EXTERNAL NETWORK RULES","-"*20)
                        print("="*88)
                        self.print_rule(self.ext_rules[rule_num])
                        print("="*88)
            else:
                if index == None:
                    print("-"*20,"RULES FOR PACKETS GOING FROM INTERNAL NETWORK","-"*20)
                    print("="*88)
                    if len(self.int_rules) > 0:
                        for idx, rule in enumerate(self.int_rules):
                            self.print_rule(rule)
                            print("-"*88)
                    else:
                        print(" "*28,"No rules written here yet!")
                    print("="*88)
                else:
                    rule_num = self.get_rule_from_index(self.int_rules, index)
                    if rule_num == None:
                        print("Invalid rule index for this set of rules! Please Try again!")
                    else:
                        print("-"*20,"RULE INDEX: ",index,", IN INTERNAL NETWORK RULES","-"*20)
                        print("="*88)
                        self.print_rule(self.int_rules[rule_num])
                        print("="*88)

    def delete_rule(self, rule_set, index):
        print("")
        if rule_set == "-e":
            rules = self.ext_rules
        else:
            rules = self.int_rules
        rule_num = self.get_rule_from_index(rules, index)
        if rule_num == None:
            print("Invalid index! Please try again!")
        else:
            print("Displaying the rule to be deleted:")
            print("-"*88)
            self.print_rule(rules[rule_num])
            print("-"*88)
            print("")
            confirmation = input("Confirm delete the above rule? [Y/N]: ")
            if confirmation == "Y":
                rules.remove(rules[rule_num])
                if rule_set == "e":
                    self.ext_rules = rules
                else:
                    self.int_rules = rules
                self.commit_changes()
            else:
                print("Deletion cancelled!")

                
