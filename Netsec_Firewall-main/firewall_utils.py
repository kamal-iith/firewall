import protocols, os, json
from ipaddress import IPv6Address

ETH_PROTO = "eth_proto"
NET_PROTO = "net_proto"
TSP_PROTO = "tsp_proto"
SRC_IP = "src_ip"
DST_IP = "dst_ip"
SRC_PORT = "src_port"
DST_PORT = "dst_port"
SRC_MAC = "src_mac"

def get_packet_details(packet):
    packet_details = {
        ETH_PROTO : "none",
        NET_PROTO : "none",
        TSP_PROTO : "none",
        SRC_IP : "none",
        DST_IP : "none",
        SRC_PORT : "none",
        DST_PORT : "none",
        SRC_MAC : "none"
    }
    protocol_queue = ['Ethernet']
    start_index: int = 0
    for protocol in protocol_queue:
        protocol_class = getattr(protocols, protocol)
        end_index: int = start_index + protocol_class.header_len
        current_protocol = protocol_class(packet[start_index:end_index])
        packet_details = current_protocol.fill_details(packet_details)
        if current_protocol.encapsulated_proto is None:
            break
        protocol_queue.append(current_protocol.encapsulated_proto)
        start_index = end_index
    return packet_details

def is_admin_packet(packet):
    try:
        packet_data = packet.decode('UTF-8')
        if packet_data[:12] == 'UPDATE_RULES':
            return True
        else:           
            return False
    except:
        return False

def get_rule_payload(cipher, packet):
    packet_data = (packet[12:]).decode('UTF-8')
    packet_data = packet_data.strip("b").strip("'")
    return cipher.decrypt(packet_data)

def verify_packet(packet_details, rules):
    for rule in rules:
        match_count = 0
        for key in rule:
            if rule[key] == "any":
                match_count += 1
            else:
                if key == ETH_PROTO or key == NET_PROTO or key == TSP_PROTO or key == SRC_MAC:
                    if packet_details[key] != "none" and rule[key] == packet_details[key]:
                        match_count += 1
                elif key == SRC_IP or key == DST_IP:
                    if packet_details[key] != "none" and check_ip(packet_details[key], rule[key]):
                        match_count += 1
                elif key == SRC_PORT or key == DST_PORT:
                    if packet_details[key] != "none" and check_port(packet_details[key], rule[key]):
                        match_count += 1
        if match_count == 8:
            return False, rule["index"]
    return True, 0

def check_port(port, port_range):
    if "-" in port_range:
        range_values = port_range.split("-")
        return int(port) >= int(range_values[0]) and int(port) <= int(range_values[1])
    else:
        return port == port_range

def check_ip(ip, rule_ip):
    if "." in ip and "." in rule_ip:
        return check_ipv4(ip, rule_ip)
    elif ":" in ip and ":" in rule_ip:
        return check_ipv6(ip, rule_ip)
    else:
        return False

def check_ipv4(ip, rule_ip):
    if "/" in rule_ip:
        [subnet_ip, mask] = rule_ip.split("/")
        mask = int(mask)
        bin_subnet = get_ip_binary(subnet_ip)
        bin_ip = get_ip_binary(ip)
        return bin_ip[:mask] == bin_subnet[:mask]
    else:
        return ip == rule_ip

def check_ipv6(ip, rule_ip):
    return IPv6Adress(ip) in IPv6Network(rule_ip, False)

def get_ip_binary(ip):
    ip_components = ip.split(".")
    bin_ip = ""
    for component in ip_components:
        bin_ip = bin_ip + '{0:08b}'.format(int(component))
    return bin_ip

def load_rules(path_to_file):
    with open(path_to_file, 'r', os.O_NONBLOCK) as rules_file:
        rules_data = json.load(rules_file)
        rules_file.close()
        return rules_data['outgoing'], rules_data['incoming'], rules_data['outgoing_last_index'], rules_data['incoming_last_index']
        
def load_logs(path_to_file):
    with open(path_to_file, 'r', os.O_NONBLOCK) as log_file:
        log_data = json.load(log_file)
        log_file.close()
        return log_data