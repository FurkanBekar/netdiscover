import scapy.all as scapy
import optparse

def banner():
    print("\n$$\   $$\          $$\          $$\$$\                                                       ")
    print("$$$\  $$ |         $$ |         $$ \__|                                                      ")
    print("$$$$\ $$ |$$$$$$\$$$$$$\   $$$$$$$ $$\ $$$$$$$\ $$$$$$$\ $$$$$$\$$\    $$\ $$$$$$\  $$$$$$\  ")
    print("$$ $$\$$ $$  __$$\_$$  _| $$  __$$ $$ $$  _____$$  _____$$  __$$\$$\  $$  $$  __$$\$$  __$$\ ")
    print("$$ \$$$$ $$$$$$$$ |$$ |   $$ /  $$ $$ \$$$$$$\ $$ /     $$ /  $$ \$$\$$  /$$$$$$$$ $$ |  \__|")
    print("$$ |\$$$ $$   ____|$$ |$$\$$ |  $$ $$ |\____$$\$$ |     $$ |  $$ |\$$$  / $$   ____$$ |      ")
    print("$$ | \$$ \$$$$$$$\ \$$$$  \$$$$$$$ $$ $$$$$$$  \$$$$$$$\\$$$$$$  | \$  /  \$$$$$$$\$$ |      ")
    print("\__|  \__|\_______| \____/ \_______\__\_______/ \_______|\______/   \_/    \_______\__|      ")

    print("\n*******************************************************************************************")
    print("\t\t\t  Author  : Furkan BEKAR\n\t\t\t  Version : 1.0\n\t\t\t  GitHub  : https://github.com/FurkanBekar")
    print("*******************************************************************************************\n")

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--interface",dest="interface",help="Your network device name",nargs=1)
    parse_object.add_option("-r","--range",dest="range",help="Scan a given range instead of auto scan. For example, 192.168.6.0/24,/16,/8",nargs=1)
    parse_object.add_option("-l","--list",dest="list",help="Scan the list of ranges  contained into the given file. Create the file so that there is a range in each line",nargs=1)
    parse_object.add_option("-p","--passive",dest="passive",help="Do not send anything, only sniff",nargs=0)
    parse_object.add_option("-m","--mac",dest="mac",help="Scan a list of known MAC's and host names into the given file. Create the file so that there is a mac or host name in each line",nargs=1)
    parse_object.add_option("-F","--filter",dest="filter",help="Customize pcap filter expression (default: ARP)",nargs=1)
    parse_object.add_option("-s","--sleep",dest="sleep",help="Time to sleep between each ARP request (miliseconds)",nargs=1)
    parse_object.add_option("-c","--count",dest="count",help="Number of times to send each ARP request (for nets with packet loss)")
    parse_object.add_option("-n","--node",dest="node",help="Last source IP octet used for scanning (from 2 to 253)")
    parse_object.add_option("-f","--fast",dest="fast",help="enable fastmode scan, saves a lot of time, recomended for auto")

    return parse_object.parse_args()

def header(number_of_answered_packets):
    print(str(number_of_answered_packets) + " Captured ARP Req/Rep packets, from " + str(number_of_answered_packets) + " hosts")
    print("-" * 80)
    print("IP                MAC Address          Len    MAC Vendor/Host Name")
    print("-" * 80)

def vendor(file_name,vendor_bytes):
    file = open(file_name)
    index = 0
    vendor = ""
    for i in file:
        if i.find(vendor_bytes) != -1:
            vendor = i[14:len(i)]
            file.close()
            break
    return vendor

def scanning_by_range(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    (answered_list,unanswered_list) = scapy.srp(combined_packet, timeout=1)

    number_of_answered_packets = len(answered_list)

    header(number_of_answered_packets)

    for i in answered_list:
        vendorr = vendor("oui.txt", str(i[1].hwsrc[0:8]).upper())

        print(i[1].psrc + " "*(18-len(i[1].psrc)) + i[1].hwsrc + "    " + str(i[1].__len__()) + " "*(7-len(str(i[1].__len__()))) + vendorr)
    print("\n   ")

def scanning_by_range_file(file_name):
    file = open(file_name)
    for i in file:
        print("Current IP range: " + i)
        scanning_by_range(i)

banner()

(input,arg) = get_user_input()

if input.interface:
    if input.range:
        scanning_by_range(input.range)
    elif input.list:
        scanning_by_range_file(input.list)
    else:
        print("[!] Our improvements are ongoing. Other features will be active as soon as possible.")
else:
    print("[!] Please enter the interface name you want to scan.")



