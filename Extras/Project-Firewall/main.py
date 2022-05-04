import os
import time
import json
import shlex
import getpass
import firewall
from colorama import Fore, Style
from netfilterqueue import NetfilterQueue

global database_filename, total_packets, packet_accepted

f = firewall.Firewall()

#performing firewall action
def commit(payload, action,):
    global packet_accepted

    if action == "ACCEPT":
        print(Fore.GREEN + "RESULT :: PACKET ACCEPTED" + Style.RESET_ALL)
        payload.accept()
        packet_accepted += 1
    else:
        print(Fore.RED + "RESULT :: PACKET DROPPED" + Style.RESET_ALL)
        payload.drop()

#callback for NFQUEUE
def cb(payload):
    global database_filename, total_packets  
    MAC = payload.get_hw()
    packet = payload.get_payload()
    total_packets += 1
    ruleNumber = -1

    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        #iterating over all rules
        if data and "rules" in data:
            for index, rule in enumerate(data["rules"]):
                if f.handle_packet(packet, MAC, rule): #check packet
                    ruleNumber = index
                    commit(payload, rule["action"])
                    break

    if ruleNumber < 0: #no rules matched
        commit(payload, "ACCEPT")

    timestamp = time.time()

    with open("log.txt", 'a', os.O_NONBLOCK) as fout:
        fout.write("{} {}\n".format(timestamp, ruleNumber))


def main(queue_num):
    open("database.json", 'a', os.O_NONBLOCK)
    open("log.txt", 'a', os.O_NONBLOCK)
    if os.stat("database.json").st_size == 0:
        open("database.json", "w").write("{}")

    global database_filename, total_packets, packet_accepted
    database_filename =  "database.json"
    total_packets = 0
    packet_accepted = 0
    #making queue and assigning callback
    nfqueue = NetfilterQueue(max_len=10000)
    nfqueue.bind(queue_num, cb)
    print("Started Firewall .... ")
    
    #calling on each packet arrival
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print
        ("Keyboard Interrupt")

    #ending of program
    nfqueue.unbind()
    print("Queue Closed\n")
    print("STATISTICS\n\tTotal Packets :: {}\n\tPackets Accepted :: {}\n\tPackets Dropped :: {}".format(total_packets, packet_accepted, total_packets - packet_accepted))

main(1)
