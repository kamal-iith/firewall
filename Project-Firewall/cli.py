import os
import re
import sys
import math
import json
import shlex
import socket
import getpass
import netaddr
import numpy as np
from IPy import IP
import matplotlib.pyplot as plt
from colorama import Fore, Style

# error checking for various fields

def is_valid_int(st):
    try:
        int(st)
        return True
    except ValueError:
        return False
        
def is_valid_port_range(port):
    if ":" in port:
        if is_valid_int(port[0:port.find(":")]) and is_valid_int(port[port.find(":")+1:]):
            return 2
        else:
            return 0
    elif is_valid_int(port):
        return 1
    else:
        return 0

def is_action_supported(action):
    return (action == "ACCEPT") or (action == "DROP")

def is_protocol_supported(protocol):
    return (protocol == 'all') or (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp')

def is_valid_IP_address(ext_addr):
    if isinstance(ext_addr, str):
        try:
            IP(ext_addr)
            return True
        except ValueError:
               return False
    else:
        try:
           socket.inet_ntoa(ext_addr)
           return True
        except socket.error:
           return False

def is_valid_MAC(addr):
    return re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower())

def get_MAC_address(addr):
    try:
        b = bytearray(addr)
        res = ""
        for x in range(0,6):
            res = res + '{:02X}'.format(int(hex(b[x]), 16)) + ":"
        res = res [:-1]
        return res
    except:
        return None

def is_valid_IP_range(data):
    if "/" in data:
        netmask = data[data.find("/")+1]
        try:
            inetmask = int(netmask)
            if inetmask < 0:
                print(Fore.YELLOW + "ERROR :: Invalid netmask `" + netmask + "` specified" + Style.RESET_ALL)
                return False
            return is_valid_IP_address(data[0:data.find("/")])
        except ValueError:
            print(Fore.YELLOW + "ERROR :: Invalid netmask `" + netmask + "` specified" + Style.RESET_ALL)
            return False
    else:
        return is_valid_IP_address(data)

def help():
    print("""\n
optional arguments:
  -p Protocol                   icmp/tcp/udp (default: any)
  -s IP_or_CIDR                 source IP ==> CIDR or complete IP (default: any)
  -sport Port_or_Port:Port      source port ==> individual or range (default: any)
  -dport Port_or_Port:Port      destination port ==> individual or range (default: any)
  -j Target                     ACCEPT/DROP (default: ACCEPT)

usage:  ADD  [-A] [-I Rule_Number] [-p Protocol] [-s IP/CIDR] [-sport Port/Port:Port]
            [-dport Port/Port:Port] [-m Source_MAC] [-j Target]
        
        UPDATE [-I Rule_Number] [-p Protocol] [-s IP/CIDR] [-sport Port/Port:Port]
            [-dport Port/Port:Port] [-m Source_MAC] [-j Target]

        DELETE all/Rule_Number

        SHOW     -- show all rules  

        CLRSCR   -- clear screen

        PLOT     -- show plot of packets processed per second vs time

        CLEAR    -- empty log.txt

        HELP

        EXIT
        \n""")

# graph plotting of PPS
def plotPPS(log_filename):
    with open(log_filename, 'r', os.O_NONBLOCK) as fin:
        lines = fin.read().split('\n')
        if len(lines) <= 1:
            print("No data point")
            return
        print("Got {} data points".format(len(lines)))

        x = [math.modf(float(lines[0].split()[0]))[1]]
        y = [1]
        for data in lines:
            if data:    
                time = math.modf(float(data.split()[0]))[1]
                if time == x[-1]:
                    y[-1] += 1
                else:
                    x.append(time)
                    y.append(1)
        x = list(range(1, len(y)+1))
        print("Maximum PPS {} at time {} ".format(np.max(y), x[np.argmax(y)]))
        plt.plot(x, y, linestyle='dashed', c='blue', label='PPS')
        plt.title("No. of packets vs time")
        plt.xlabel("time")
        plt.ylabel("#packets")
        plt.legend(loc='best')
        plt.show()

# show rules
def showStatistics(database_filename):
    print("Chain INPUT (policy DROP)")
    print("{0: <7}\t{1: <6}\t{2: <4}\t{3: <18}\t{4: <20}\t".format('Rule-No','target','prot', 'Source-IP', 'Source-MAC'))
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        try:
            data = json.load(fin)
            for index,rule in enumerate(data["rules"]):
                print("{0: <7}\t{1: <6}\t{2: <4}\t{3: <18}\t{4: <20}\t".format(index,rule["action"],rule["protocol"], rule["sourceip"], rule["mac"]), end='')
                if rule["sport1"]:
                    if rule["sport1"] == rule["sport2"]:
                        print('spt {}  '.format(rule["sport1"]), end='')
                    else:
                        print('spt {}:{}  '.format(rule["sport1"],rule["sport2"]), end='')
                if rule["dport1"]:
                    if rule["dport1"] == rule["dport2"]:
                        print('dpt {}  '.format(rule["dport1"]), end='')
                    else:
                        print('dpt {}:{}  '.format(rule["dport1"],rule["dport2"]), end='')
                print('')        
        except:
            print("No JSON data in rule file")

def deleteRule(database_filename, rule):
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        if rule == None:
            data["rules"] = []
        else:
            if rule < 0 or rule >= len(data["rules"]):
                print("Rule with Rule-no {} not found".format(rule))
                return
            data["rules"].pop(rule)
        with open(database_filename, 'w', os.O_NONBLOCK) as fout:
            json.dump(data, fout)
            fout.close()
            print(Fore.GREEN + "\tUPDATED RULE "+ Style.RESET_ALL)
        fin.close()
            
# read params from CLI            
def getParams(rule):
    protocol, sourceip, sport1, sport2, dport1, dport2, MAC, action = "all", "any", None, None, None, None, "any", "ACCEPT"

    if "-p" in rule:
        index = rule.index("-p")
        if is_protocol_supported(rule[index+1]):
            protocol = rule[index+1].lower()
        else:
            print("ERROR :: Protocol `%s` not supported." %(rule[index+1]))
            return None

    if "-s" in rule:
        index = rule.index("-s")
        if is_valid_IP_range(rule[index+1]):
            sourceip = rule[index+1]
        else:
            print("ERROR :: Source IP `%s` is incorrect." %(rule[index+1]))
            return None

    if "-m" in rule:
        index = rule.index("-m")
        if is_valid_MAC(rule[index+1]):
            MAC = rule[index+1].upper()
        else:
            print("ERROR :: Source MAC `%s` is incorrect." %(rule[index+1]))
            return None

    if "-dport" in rule:
        if protocol ==  "icmp":
            print("ERROR :: Destination Port cannot be used with ICMP")
            return None

        index = rule.index("-dport")
        valid = is_valid_port_range(rule[index+1])
        if valid == 2:
            dport1 = int(rule[index+1][:rule[index+1].index(":")])
            dport2 = int(rule[index+1][rule[index+1].index(":") + 1:])
        elif valid == 1:
            dport1 = int(rule[index+1])
            dport2 = dport1      
        else:
            print("ERROR :: Destination Port `%s` is incorrect." %(rule[index+1]))
            return None

    if "-sport" in rule:
        if protocol ==  "icmp":
            print("ERROR :: Source Port cannot be used with ICMP")
            return None

        index = rule.index("-sport")
        valid = is_valid_port_range(rule[index+1])
        if valid == 2:
            sport1 = int(rule[index+1][:rule[index+1].index(":")])
            sport2 = int(rule[index+1][rule[index+1].index(":") + 1:])
        elif valid == 1:
            sport1 = int(rule[index+1])
            sport2 = sport1      
        else:
            print("ERROR :: Source Port `%s` is incorrect." %(rule[index+1]))
            return None

    if "-j" in rule:
        index = rule.index("-j")
        if is_action_supported(rule[index+1].upper()):
            action = rule[index+1].upper()
        else:
            print("ERROR :: Action `%s` is not supported." %(rule[index+1]))
            return None
    return {"protocol":protocol,"sourceip":sourceip,"sport1":sport1,"sport2":sport2,"dport1":dport1,"dport2":dport2,"mac":MAC,"action":action}

# add rule to file 
def setRule(database_filename, rule, newRule, isUpdate = False):  
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        if data:
            if "-I" in rule:
                pos = rule[rule.index("-I")+1]
                if not is_valid_int(pos):
                    print("ERROR :: -I rule incorrect index")
                    return

                pos = int(pos)
                if pos < 0 or pos >= len(data["rules"]):
                    print("ERROR :: out of range for Rule Number")
                    return
                
                if isUpdate:
                    data["rules"][pos] = newRule
                else:    
                    data["rules"].insert(pos, newRule)
            else:
                data["rules"].append(newRule)
        else:
            data = { "rules" : [newRule]}
        fin.close()
        with open(database_filename, 'w', os.O_NONBLOCK) as fout:
            json.dump(data, fout)
            fout.close()
            print(Fore.GREEN + "\tUPDATED RULE "+ Style.RESET_ALL)

#read from user
def getInput(database_filename, log_filename):
    print(Fore.GREEN + "%s:~/# "%(getpass.getuser()) + Style.RESET_ALL, end='')
    rule = shlex.split(input())
    if len(rule) == 0:
      print("ERROR :: No input")
    else:
        action = rule[0].lower()
        if action == "clrscr":
            os.system('clear')
        elif action == "clear":
            open(log_filename, 'w').close()            
        elif action == "exit":
            sys.exit()    
        elif action == "plot":
            plotPPS(log_filename)
        elif action == "help":
            help()
        elif action == "show":
            showStatistics(database_filename)
        elif action == "delete":
            if len(rule) == 2:
                if(rule[1].lower() == "all"):
                    deleteRule(database_filename, None)
                elif not is_valid_int(rule[1]):
                    print("ERROR :: Incorrect input")
                else:
                    deleteRule(database_filename, (int)(rule[1]))
            else:
                print("ERROR :: Incorrect input")
        elif action == "update":
            if "-A" in rule:
                print("ERROR :: Incorrect input. cannot append")
            elif not "-I" in rule:
                print("ERROR :: Incorrect input. -I not present")
            else:
                newRule = getParams(rule)
                if newRule:
                    setRule(database_filename, rule, newRule, True)
        elif action == "add":
            newRule = getParams(rule)
            if newRule:
                setRule(database_filename, rule, newRule)
        else:
            print("ERROR :: Incorrect action")

if __name__ == "__main__":
    open("database.json", 'a', os.O_NONBLOCK)
    open("log.txt", 'a', os.O_NONBLOCK)
    if os.stat("database.json").st_size == 0:
        open("database.json", "w").write("{}")
    
    help()
    while True:
        getInput("database.json", "log.txt")

