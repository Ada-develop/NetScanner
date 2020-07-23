#!/usr/bin/env/ python
import scapy.all as scapy
print("Enter the IP that you want to scan : ")
ip_input = input()

def scan(ip):
    arp_request = scapy.ARP(pdst = ip) # Scanning ARP by IP
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # Scanning ARP by broadcast MAC | ip a
    arp_request_broadcast = broadcast/arp_request # Combine IP / MAC requests
    answered_list =  scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # scapy.srp() send/recieve packets | [0] for answered [1] for unanswered
    
    #Parse : 
    print("IP\t\t\tMAC Address\n---------------------------------------------------")
    for element in answered_list: #Parse getted data 
         print(element[1].psrc +"\t\t" + element[1].hwsrc) #Answer by documentation contains two lists, first[0] is request , so we don't need this so we use element[1]
         print("---------------------------------------------------")# As using element[1].show() we see all available data, but for us valuable is only psrc & hwsrc
    
#"192.168.1.1/24"
scan(ip_input + "/24")
