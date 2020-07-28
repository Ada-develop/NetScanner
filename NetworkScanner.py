#!/usr/bin/env/ python
import scapy.all as scapy
from optparse import OptionParser

parser = OptionParser()

print("Enter the IP that you want to scan : ")
ip_input = input()
print("Set the range , options 8 / 16 / 24 :"  )
ranger = input()

def scan(ip):
    arp_request = scapy.ARP(pdst = ip) # Scanning ARP by IP
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # Scanning ARP by broadcast MAC | ip a
    arp_request_broadcast = broadcast/arp_request # Combine IP / MAC requests
    answered_list =  scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # scapy.srp() send/recieve packets | [0] for answered [1] for unanswered
    
    #Parse : 
    
    clients_list = []
    for element in answered_list: #Parse getted data 
         client_dict = {"ip":element[1].psrc,"mac": element[1].hwsrc} #Answer by documentation contains two lists, first[0] is request , so we don't need this so we use element[1]
         clients_list.append(client_dict) # As using element[1].show() we see all available data, but for us valuable is only psrc & hwsrc
    return clients_list

def print_results(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

#"IP" + range
scan_result = scan(ip_input + "/" +ranger)
print_results(scan_result)