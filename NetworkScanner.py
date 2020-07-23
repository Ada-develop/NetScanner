#!/usr/bin/env/ python
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst = ip) # Scanning ARP by IP
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # Scanning ARP by broadcast MAC
    arp_request_broadcast = broadcast/arp_request # Combine IP / MAC requests
    answered_list =  scapy.srp(arp_request_broadcast, timeout=10)[0] # scapy.srp() send/recieve packets | [0] for answered [1] for unanswered
    
    for element in answered_list:
         print(element[1].psrc)
         print(element[1].hwsrc)
         print("---------------------------------------------------")
    

scan("192.168.1.1/24")
