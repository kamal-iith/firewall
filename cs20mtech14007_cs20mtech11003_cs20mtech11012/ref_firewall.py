#! /usr/bin/env python3
import socket 
import sys
import os
import ctypes
import fcntl
import threading
import struct  
import json 

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


def get_ip(addr):
    return '.'.join(map(str, addr))

def ethernet_header(raw_data):   
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = dest.hex(':')
    src_mac = src.hex(':')
    proto = socket.ntohs(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def ipv4_header(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15 )*4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) 
    data = raw_data[header_length:]
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, data  

def tcp_header(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) =struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def icmp_header(raw_data):
    type1, code, check_sum, other = struct.unpack('! s s 2s 4s', raw_data[:8]) 
    return type1, code, check_sum, other

def udp_header(raw_data):
    st = struct.unpack('! H H H H',raw_data[:8])
    sport = st[0]
    dport = st[1]
    length = st[2]
    checksum = st[3]
    return sport, dport, length, checksum

def packet_parse(raw_data):
    dict1 = {}
    eth = ethernet_header(raw_data)
    dict1["destination_mac"] = eth[0]
    dict1["source_mac"] = eth[1]

    if eth[2] == 8:
        ipv4 = ipv4_header(eth[3])
        dict1["source_ip"] = ipv4[4]
        dict1["destination_ip"] = ipv4[5]    
        if ipv4[3] == 6:        #tcp        
            print("Tcp packet")
            dict1["protocol"] = "TCP"
            tcp = tcp_header(ipv4[6])
            dict1["source_port"] = tcp[0]
            dict1["destination_port"] = tcp[1]
        elif ipv4[3] == 1:      #icmp
            print("ICMP packet")
            dict1["protocol"] = "ICMP"
            icmp = icmp_header(ipv4[6])
        elif ipv4[3] == 17:     #udp 
            print("UDP packet")
            dict1["protocol"] = "UDP"
            udp = udp_header(ipv4[6])
            dict1["source_port"] = udp[0]
            dict1["destination_port"] = udp[1]
    elif eth[2] == 1544:
        print("ARP packet")
        
    return dict1
    
    
                
def validate(dict1):
    fd = open("rules.json", "r")
    data = json.load(fd)
    fd.close()
    #print(dict1)
    try:
        for ip in data["restricted_src_ip"]:
            if ip==dict1.get("source_ip") :
                return 0
    finally:
        pass

    try:
        for ip in data["restricted_dest_ip"]:
            if ip==dict1.get("destination_ip") :
                return 0
    finally:
        pass

    try:
        for port in data["restricted_src_ports"]:
            if port==dict1.get("source_port") :
                return 0
    finally:
        pass
    
    try:
        for port in data["restricted_dest_ports"]:
            if port==dict1.get("destination_port") :
                return 0
    finally:
        pass

    try:        
        for proto in data["restricted_protocols"]:
            if proto==dict1.get("protocol") :
                return 0
    finally:
        pass
    
    try:
        for mac in data["restricted_src_mac"]:
            if mac==dict1.get("source_mac") :
                return 0
    finally:
        pass

    try:    
        for mac in data["restricted_dest_mac"]:
            if mac==dict1.get("destination_mac") :
                return 0
    finally:
        pass

    return 1

          

def send_recv2(sock1,sock2):
    while True:
        raw_data = sock2.recvfrom(1514) 
        dict1 = packet_parse(raw_data[0])
        if validate(dict1) == 1:
            sock1.sendall(raw_data[0])      #send if rules satisfied 
        else:
            print("Packet drop")

def send_recv1(sock1,sock2):
    while True:
        raw_data = sock1.recvfrom(1514)
        dict1 = packet_parse(raw_data[0])
        if validate(dict1) == 1:
            sock2.sendall(raw_data[0])      #send if rules satisfied
        else:
            print("Packet drop")

def add_rules():
    fd = open("rules.json", "r")
    data = json.load(fd)
    fd.close()

    print("1. Restrict Source IP \n2. Restrict Destination IP \n3. Restrict Source Port \n4. Restrict Destination Port \n5. Restrict Protocols \n6. Restrict Source MAC \n7. Restrict Destination MAC")   

    choice = int(input("Enter choice: ")) 

    if choice == 1: 
        ip =  input("Enter ip: ")
        data["restricted_src_ip"].append(ip)  
    elif choice == 2: 
        ip =  input("Enter ip: ")
        data["restricted_dest_ip"].append(ip)
    elif choice== 3: 
        port = input("Enter port: ")   
        data["restricted_src_ports"].append(port)     
    elif choice== 4: 
        port = input("Enter port: ")
        data["restricted_dest_ports"].append(port)
    elif choice== 5: 
        porto = input("Enter Protocol: ")
        data["restricted_protocols"].append(proto)
    elif choice== 6:
        mac = input("Enter MAC: ")
        data["restricted_src_mac"].append(mac)        
    elif choice== 7: 
        mac = input("Enter MAC: ")
        data["restricted_dest_mac"].append(mac)
    
    fd = open("rules.json","w")
    json.dump(data,fd)
    fd.close()

def delete_rules():
    fd = open("rules.json", "r")
    data = json.load(fd)
    fd.close()

    print("1. Restrict Source IP \n2. Restrict Destination IP \n3. Restrict Source Port \n4. Restrict Destination Port \n5. Restrict Protocols \n6. Restrict Source MAC \n7. Restrict Destination MAC")   

    choice = int(input("Enter choice: ")) 

    if choice == 1: 
        ip =  input("Enter ip: ")
        data["restricted_src_ip"].remove(ip)  
    elif choice == 2: 
        ip =  input("Enter ip: ")
        data["restricted_dest_ip"].remove(ip)
    elif choice== 3: 
        port = input("Enter port: ")   
        data["restricted_src_ports"].remove(port)     
    elif choice== 4: 
        port = input("Enter port: ")
        data["restricted_dest_ports"].remove(port)
    elif choice== 5: 
        porto = input("Enter Protocol: ")
        data["restricted_protocols"].remove(proto)
    elif choice== 6:
        mac = input("Enter MAC: ")
        data["restricted_src_mac"].remove(mac)        
    elif choice== 7: 
        mac = input("Enter MAC: ")
        data["restricted_dest_mac"].remove(mac)
    
    fd = open("rules.json","w")
    json.dump(data,fd)
    fd.close()

def show_stats():
    fd = open("rules.json", "r")
    data = json.load(fd)
    fd.close()
    print("Enter rule number of Stat to be shown: ")
    print("1. Restrict Source IP \n2. Restrict Destination IP \n3. Restrict Source Port \n4. Restrict Destination Port \n5. Restrict Protocols \n6. Restrict Source MAC \n7. Restrict Destination MAC")   

    choice = int(input("Enter choice: ")) 

    if choice == 1: 
        print(data["restricted_src_ip"])  
    elif choice == 2: 
        print(data["restricted_dest_ip"])
    elif choice== 3: 
        print(data["restricted_src_ports"])     
    elif choice== 4: 
        print(data["restricted_dest_ports"])
    elif choice== 5: 
        print(data["restricted_protocols"])
    elif choice== 6:
        print(data["restricted_src_mac"])        
    elif choice== 7: 
        print(data["restricted_dest_mac"])

def main():
    while True:
        print("Select from menu:")
        print("1. Start Firewall")
        print("2. Manage Rules ")
        print("3. Exit")

        choice =  int(input("Enter your choice: "))

        if choice == 1:
            interface_1 = 'ens1'
            interface_2 = 'ens2'
            ETH_P_ALL = 3
            action = 0          # action = 0 drop and
                                # action = 1 pass through 
            IFF_PROMISC = 0x100
            SIOCGIFFLAGS = 0x8913
            SIOCSIFFLAGS = 0x8914

            ifr1 = ifreq()
            ifr1.ifr_ifrn = bytes(interface_1, 'UTF-8')

            ifr2 = ifreq()
            ifr2.ifr_ifrn = bytes(interface_2, 'UTF-8')


            s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            s1.bind((interface_1, 0))

            s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            s2.bind((interface_2, 0))


            fcntl.ioctl(s1.fileno(), SIOCGIFFLAGS, ifr1) # G for Get
            fcntl.ioctl(s2.fileno(), SIOCGIFFLAGS, ifr2) 

            ifr1.ifr_flags |= IFF_PROMISC
            ifr2.ifr_flags |= IFF_PROMISC

            fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr1) # S for Set
            fcntl.ioctl(s2.fileno(), SIOCSIFFLAGS, ifr2)
            
            print("Firewall is Running ")


            try:
                t1 = threading.Thread(target = send_recv1, args = (s1,s2,) )
                t1.start()
                t2 = threading.Thread(target = send_recv2, args = (s1,s2,) )
                t2.start()   
                t1.join()
                t2.join()
            finally:
                ifr1.ifr_flags &= ~IFF_PROMISC
                fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr1)
                ifr2.ifr_flags &= ~IFF_PROMISC
                fcntl.ioctl(s2.fileno(), SIOCSIFFLAGS, ifr2)
                s1.close()
                s2.close()
        elif choice == 2:
            print("1. Add Rule \n2. Delete Rule \n3. Update Rule \n4. Show Statistics")
            choice = int(input("Enter your choice: "))
            if choice == 1 :
                add_rules()
            elif choice==2:
                delete_rules()
            elif choice==3:
                pass
            elif choice==4:
                show_stats()
            else:
                print("Enter Valid Choice")

        elif choice==3:
            exit(0)
            
        else:
            print("Enter Valid Choice")



if __name__ == "__main__":
    main()
