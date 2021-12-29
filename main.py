import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # create a ethernet object with the address set to the broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # append the arp_request to the broacast, creating a new package
    arp_request_broadcast = broadcast/arp_request
    # send and receive the response
    # see that we are not specifying the address here, the srp fn knows the address because we added a ethernet layer and we have setted a MAC address (the broadcast MAC) there
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    print("IP\t\t\tMAC Address")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)


scan("172.16.239.1/24")
