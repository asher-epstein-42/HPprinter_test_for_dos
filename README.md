# HPprinter_test_for_dos





#The porpose of this script is to check if someone is trying to connect to a HP printer over the network,
#and in case of detection -> perform a dos(denial of service) attack on the hp printer
#first we are scanning the network for hp devices by their mac address(mac address of hp devices starts with #9C:7B:EF), but we cant determine the type of the device this way, so we are checking if the raw
#printing port(9100) is open -> there for this is a hp printer (because it uses raw printing protocol)  
#for every hp device we check if this is a printer by performing a stealth scan using our capturd destination IP address and port 9100 (raw ptinting) over tcp to see if we manage to get any response
# if it is a hp printer, were going to send a reset and start a dos attack(SYN Flooding Attack ).	
