# HPprinter_test_for_dos



#The porpose of this script is to check if someone is trying to connect to a HP printer over the network,
#and in case of detection -> perform a dos(denial of service) attack on the hp printer
# first, we are sniffing using scapy to check if someone is trying to connect to a hp device.
# because you can't determine the type of the hp device by the mac address (only that this is a hp device
# - mac address of hp devices starts with 9C:7B:EF)
# we are going to preferm a stealth scan using our capturd destination IP address and port 9100 (raw ptinting) over tcp to see if we manage to get any response
# - there for this is a hp printer (because it uses raw printing protocol).
# if it is a hp printer, were going to send a reset and start a dos attack.		
