import socket, select, json, time, os, bisect, math, queue as Queue
import firewall_utils as utils
from cipher import Cipher
from getpass import getpass

class Firewall:
    def __init__(self, int_interface, ext_interface, rule_file, password, tolerence=200):
        self.password = password
        self.rule_file = rule_file
        self.cipher = Cipher(password)
        self.int_interface = int_interface
        self.ext_interface = ext_interface
        self.int_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.ext_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.lp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.icmp_list = []
        self.icmp_tolerance = tolerence
        self.icmp_block = False
        self.icmp_block_start = 0
        self.start_time = math.floor(time.time())
        self.logs = {
            "total_packets": 0,
            "total_dropped": 0,
            "max_pps": 0,
            "traffic":{},
            rule_file : {
                "internal":{
                    "total_packets": 0,
                    "total_dropped": 0
                },
                "external":{
                    "total_packets": 0,
                    "total_dropped": 0
                }
            },
            "icmp_floods": 0,
            "icmp_dropped": 0
        }
        try:
            self.int_socket.bind((self.int_interface, 0))
            self.ext_socket.bind((self.ext_interface, 0))
            self.lp_socket.bind(('127.0.0.1',55430))
            self.lp_socket.listen()
            self.int_socket.setblocking(0)
            self.ext_socket.setblocking(0)
            self.lp_socket.setblocking(0)
            self.sockets = [self.int_socket, self.ext_socket, self.lp_socket]
            self.output_queues = {
                self.int_socket : Queue.Queue(),
                self.ext_socket : Queue.Queue()
            }
            self.output_list = []
            self.int_rules, self.ext_rules, _, _ = utils.load_rules(self.rule_file)       
            self.start_firewall()
        except Exception as e:
            self.int_socket.close()
            self.ext_socket.close()
            self.lp_socket.close()
            print("")
            print("Exception occurred! ", e)
            print("Aborting!")

    def start_firewall(self):
        while True:
            try:
                readable, writable, exceptional = select.select(self.sockets, self.output_list, self.sockets)
                for s in readable:
                    if s is self.lp_socket:
                        lp_connection,addr = s.accept()
                        self.sockets.append(lp_connection)
                    else:
                        raw_packet = s.recv(2048)
                        recv_time = time.time()
                        recv_sec = math.floor(recv_time)-self.start_time
                        if recv_sec in self.logs["traffic"]:
                            self.logs["traffic"][recv_sec] += 1
                        else:
                            self.logs["traffic"][recv_sec] = 1
                        self.logs["total_packets"] += 1
                        
                        if s is self.int_socket:
                            self.logs[self.rule_file]["internal"]["total_packets"] += 1
                            packet_details = utils.get_packet_details(raw_packet)
                            verification, indx = utils.verify_packet(packet_details, self.int_rules)
                            if verification:
                                self.output_queues[self.ext_socket].put(raw_packet)
                                if self.ext_socket not in self.output_list:
                                    self.output_list.append(self.ext_socket)
                            else: 
                                print("Packet dropped on internal interface, ",self.int_interface,'\n')
                                print(packet_details,'\n')
                                self.drop_packet(indx, "internal")
                        elif s is self.ext_socket:
                            self.logs[self.rule_file]["external"]["total_packets"] += 1
                            packet_details = utils.get_packet_details(raw_packet)
                            verification, indx = utils.verify_packet(packet_details, self.ext_rules)
                            if verification:
                                if packet_details[utils.NET_PROTO] == "ICMP":
                                    self.handle_ICMP(raw_packet, recv_time)
                                else:
                                    self.output_queues[self.int_socket].put(raw_packet)
                                    if self.int_socket not in self.output_list:
                                        self.output_list.append(self.int_socket)
                            else: 
                                print("Packet dropped on external interface ",self.ext_interface,'\n')
                                print(packet_details, '\n')
                                self.drop_packet(indx, "external")
                        else:
                            if raw_packet != "":
                                if utils.is_admin_packet(raw_packet): 
                                    rule_payload = utils.get_rule_payload(self.cipher, raw_packet)
                                    if rule_payload != "" and ("RULE_FILE:" in rule_payload):
                                        print("-"*10," RULES UPDATE RECEIVED ", "-"*10,"\n")
                                        self.rule_file = rule_payload[10:]
                                        self.logs[self.rule_file] = {
                                            "internal":{
                                                "total_packets": 0,
                                                "total_dropped": 0
                                            },
                                            "external":{
                                                "total_packets": 0,
                                                "total_dropped": 0
                                            }
                                        }
                                        self.int_rules, self.ext_rules, _, _ = utils.load_rules(self.rule_file)
                            else:
                                s.close()
                                self.sockets.remove(s)
                        done_time = time.time()
                        pps = 1/(done_time-recv_time)
                        if pps>self.logs["max_pps"]:
                            self.logs["max_pps"] = pps
                            self.dump_logs()
                for s in writable:
                    try:
                        next_msg = self.output_queues[s].get_nowait()
                    except Queue.Empty:
                        self.output_list.remove(s)
                    else:
                        s.send(next_msg)
                for s in exceptional:
                    if s is self.int_socket or s is self.ext_socket or s is self.lp_socket:
                        current_interface = self.int_interface
                        if s is self.ext_socket:
                            current_interface = self.ext_interface
                        print("An exception occurred in the interface,",current_interface)
                        break
                    else:
                        s.close()
                        self.sockets.remove(s)
            except KeyboardInterrupt:       
                print("")
                abort_conf = input("Keyboard interrupt! Abort firewall? [Y/N]: ")
                if abort_conf == "Y":
                    abort_pswd = getpass(prompt="Please enter the firewall authentication password: ")
                    if abort_pswd == self.password:
                        self.int_socket.close()
                        self.ext_socket.close()
                        self.lp_socket.close()
                        self.dump_logs()
                        print("Password match! Aborting!")
                        break
                    else:
                        print("Invalid password! cancelling abort!")
                        pass
                else:
                    pass

    def handle_ICMP(self, packet, time_stamp):
        if not self.icmp_block:
            self.icmp_list.append(time_stamp)
            indx = bisect.bisect_left(self.icmp_list, time_stamp-120)
            self.icmp_list = self.icmp_list[indx:]
            last_count = len(self.icmp_list)
            if last_count < self.icmp_tolerance:
                self.output_queues[self.int_socket].put(packet)
                if self.int_socket not in self.output_list:
                    self.output_list.append(self.int_socket)
            else:
                print('\n',"-"*10, "ICMP FLOOD DETECTED", "-"*10,'\n')
                self.icmp_block = True
                self.icmp_block_start = time.time()
                self.logs["icmp_floods"] += 1
                self.logs["icmp_dropped"] += 1
                self.dump_logs()
        else:
            if time_stamp - self.icmp_block_start < 3600:
                self.logs["icmp_dropped"] += 1
                self.dump_logs()
            else:
                self.icmp_block = False
                self.icmp_block_start = 0
                self.output_queues[self.int_socket].put(packet)
                if self.int_socket not in self.output_list:
                    self.output_list.append(self.int_socket)

    def drop_packet(self,rule_index, interface):
        self.logs["total_dropped"] += 1
        self.logs[self.rule_file][interface]["total_dropped"] += 1
        if rule_index in self.logs[self.rule_file][interface]:
            self.logs[self.rule_file][interface][rule_index] += 1
        else:
            self.logs[self.rule_file][interface][rule_index] = 1  
        self.dump_logs()

    def dump_logs(self):
        with open('logs.json', 'w', os.O_NONBLOCK) as log_file:
            json.dump(self.logs, log_file)
            log_file.close()





    

