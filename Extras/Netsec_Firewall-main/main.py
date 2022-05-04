#!/usr/bin/env python3

from rules_io import Rules
from firewall import Firewall
from getpass import getpass
from cipher import Cipher
import socket, os, sys, json, firewall_utils as utils, numpy as np
import plotext as plt

def main():
    arg_len = len(sys.argv)
    if arg_len < 2:
        print_usage()
    else:
        if sys.argv[1] == "run":
            if arg_len != 8 and arg_len!= 10:
                print_usage()
            else:
                icmp_tol = 200
                if arg_len == 10:
                    icmp_tol = int(sys.argv[9])
                int_inf = sys.argv[3]
                ext_inf = sys.argv[5]
                file_path = sys.argv[7]
                print("")
                password = getpass(prompt="Please enter an authentication password. This password must be provided whenever rule changes need to be applied: ")
                pswd_conf = getpass(prompt="Re-enter the same password for confirmation: ")
                while password != pswd_conf:
                    pswd_conf = getpass(prompt="Passwords not matching! Re-enter the password for confirmation: ")
                print("")
                Firewall(int_inf, ext_inf, file_path, password, tolerence=icmp_tol)
        elif sys.argv[1] == "rules":
            if arg_len < 5 or sys.argv[2] != "-f":
                print_usage()
            else:
                file_path = sys.argv[3]
                if sys.argv[4] == "-create":
                    create_new(file_path)
                else:
                    io = Rules(file_path)
                    if sys.argv[4] == "-add":
                        io.add()
                    elif sys.argv[4] == "-apply":
                        password = getpass(prompt="Please enter the firewall authentication password: ")
                        apply_rules(file_path, password)
                    elif sys.argv[4] == "-update":
                        if arg_len != 8:
                            print_usage()
                        else:
                            rule_set = sys.argv[5]
                            rule_index = int(sys.argv[7])
                            io.edit_rule(rule_set, rule_index)
                    elif sys.argv[4] == "-delete":
                        if arg_len != 8:
                            print_usage()
                        else:
                            rule_set = sys.argv[5]
                            rule_index = int(sys.argv[7])
                            io.delete_rule(rule_set, rule_index)
                    elif sys.argv[4] == "-show":
                        rule_set = None
                        rule_index = None
                        if arg_len == 6:
                            rule_set = sys.argv[5]
                        if arg_len == 8:
                            rule_set = sys.argv[5]
                            rule_index = int(sys.argv[7])
                        io.show_rules(rule_set, rule_index)
        elif sys.argv[1] == "logs":
            if arg_len < 3:
                print_usage()
            else:
                if arg_len == 3:
                    show_statistics()
                elif arg_len == 5:
                    file_path = sys.argv[4]
                    show_statistics(rule_file=file_path)
                elif arg_len == 6:
                    file_path = sys.argv[4]
                    rule_set = sys.argv[5]
                    show_statistics(rule_file=file_path, rule_set=rule_set)
                elif arg_len == 8:
                    file_path = sys.argv[4]
                    rule_set = sys.argv[5]
                    rule_indx = sys.argv[7]
                    show_statistics(rule_file=file_path, rule_set=rule_set, indx=rule_indx)
                else:
                    print_usage()


        else:
            print_usage()



def print_usage():
    print("""
usage:  run -i [internal network interface] -e [external network interface] 
                    -f [path to rules] <optional -t [icmp_tolerance]>

        rules -f [path to rules] -create

        rules -f [path to rules] -add

        rules -f [path to rules] -update -[i/e] -r [rule_index]

        rules -f [path to rules] -delete -[i/e] -r [rule_index]

        rules -f [path to rules] -apply

        rules -f [path to rules] -show <optional [-i/e] [-r rule_index]>

        logs -show_stats <optional -f [path to rules] [-i/e] [-r rule_index]>""")
    print("")

def create_new(file_path):
    print("")
    with open(file_path, 'w', os.O_NONBLOCK) as rule_file:
        json.dump({
            "incoming": [], 
            "outgoing": [],
            "incoming_last_index": 0,
            "outgoing_last_index": 0,
        }, rule_file)
        rule_file.close()
    print("Sucessfully created an empty rule file")

def apply_rules(file_path, password):
    lp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lp_socket.connect(('127.0.0.1', 55430))
    encrypted_msg = Cipher(password).encrypt("RULE_FILE:"+file_path)
    final_msg = "UPDATE_RULES"+str(encrypted_msg)
    lp_socket.sendall(final_msg.encode('UTF-8'))
    lp_socket.close()

def show_statistics(rule_file=None, rule_set=None, indx=None):
    interface = None
    if rule_set == "-e":
        interface = "external"
    elif rule_set == "-i":
        interface = "internal"
    logs = utils.load_logs('logs.json')
    print("")
    print("-"*13,"OVERALL FIREWALL STATISTICS","-"*13)
    print("TOTAL PACkETS RECEIVED BY THE FIREWALL: ", logs["total_packets"])
    print("TOTAL PACkETS DROPPED BY THE FIREWALL: ", logs["total_dropped"])
    if rule_file != None:
        if interface != None:
            print("")
            print("-"*12,interface.upper(),"INTERFACE STATISTICS","-"*12)
            print("TOTAL PACKETS RECEIVED ON",interface.upper(),"INTERFACE: ", logs[rule_file][interface]["total_packets"])
            print("TOTAL PACKETS DROPPED ON",interface.upper(),"INTERFACE: ", logs[rule_file][interface]["total_dropped"])
            if indx != None:
                if indx in logs[rule_file][interface]:
                    print("\nTOTAL PACKETS DROPPED DUE TO RULE",indx,"ON",interface.upper(),"INTERFACE :",logs[rule_file][interface][indx])
                else:
                    print("Invalid rule index!")
        else:
            print("")
            print("-"*12,"EXTERNAL INTERFACE STATISTICS","-"*12)
            print("TOTAL PACKETS RECEIVED ON EXTERNAL INTERFACE: ", logs[rule_file]["external"]["total_packets"])
            print("TOTAL PACKETS DROPPED ON EXTERNAL INTERFACE: ", logs[rule_file]["external"]["total_dropped"])
            print("")
            print("-"*12,"INTERNAL INTERFACE STATISTICS","-"*12)
            print("TOTAL PACKETS RECEIVED ON INTERNAL INTERFACE: ", logs[rule_file]["internal"]["total_packets"])
            print("TOTAL PACKETS DROPPED ON INTERNAL INTERFACE: ", logs[rule_file]["internal"]["total_dropped"])
    else:
        print("")
        print("-"*16, "ICMP FLOOD STATISTICS", "-"*16)
        print("FLOODS ENCOUNTERED SO FAR: ", logs["icmp_floods"])
        print("PACKETS DROPPED DURING ICMP BLOCK:", logs["icmp_dropped"])
        print("")
        print("-"*22,"PPS INFO","-"*22)
        print("MAXIMUM PPS SO FAR: ",logs["max_pps"])
        print("")
        title = "-"*18+"NETWORK TRAFFIC"+"-"*18
        net_traffic = logs["traffic"]
        max_sec = max(np.array(list(net_traffic.keys())).astype(int))
        packets_num = np.zeros(max_sec+1)
        for i in net_traffic:
            packets_num[int(i)] = net_traffic[i]
        packets_num = packets_num.astype(int)
        plt.scatter(np.arange(max_sec+1),packets_num, fillx=True)
        plt.figsize(80, 20)
        plt.title(title)
        plt.xlabel("Time")
        plt.ylabel("Packets")
        plt.show()
 
main()
