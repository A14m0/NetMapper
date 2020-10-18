# this is a really slow network scanner. 
# the idea is that it will slowly poke around and check who's up and whos not
# over the course of a while, ideally without being discoverd or tripping over 
# network detection systems. who knows if it works

import socket as s
import netifaces
import netaddr
import time
import sys
from random import randint, random

# some random ports to try to connect to while working
random_ports = [80, 443, 8080, 22, 53]

# generates a list of all valid IP addresses on the network
def generate_targets(interface):
    targets = []
    netstr = ""

    # generate the network string
    addr = netifaces.ifaddresses(interface)[2][0]['addr']
    netmask = netifaces.ifaddresses(interface)[2][0]['netmask']

    mask = [int(x) for x in netmask.split(".")]
    cidr = sum((bin(x).count('1') for x in mask))

    netstr = "{}/{}".format(addr, cidr)

    # add all of the valid hosts on the network to the target list
    net = netaddr.IPNetwork(netstr)

    for i in net.iter_hosts():
        targets.append(str(i))

    return targets


if len(sys.argv) != 2:
    print("[ERROR] Illegal argument count")
    print("Usage: {} <interface>".format(sys.argv[0]))
    sys.exit(1)
else:
    interface = sys.argv[1]


ips = generate_targets(interface)

sock = s.socket(s.AF_INET, s.SOCK_STREAM)
#sock.setsockopt()

alive_ips = []
num_ips = len(ips)
total_done = 0

# loop over the addresses
for i in range(num_ips):
    # cleans the screen of crap
    print(" " * 40, end="\r")


    # randomly choose an ip from the list
    address = ips[randint(0, len(ips)-1)]
    # try to connect on random known port
    try:
        port = random_ports[randint(0, len(random_ports)-1)]
        print("[INFO] Trying {} on {}\t\t{:>.1f}%".format(address, port, total_done/len(ips)), end='\r')

        sock.connect((address, port))
        
        # what are the chances we get this far without exceptions? 
        # low... but not impossible
        sock.close()
        alive_ips.append(address)
        print("[INFO] Address '{}' is up AND port '{}' is open".format(address, port))
    
    # host is up and port is closed
    except ConnectionRefusedError:
        alive_ips.append(address)
        print("[INFO] Address '{}' is up".format(address))

    # host is down
    except OSError:
        pass

    # user interrupt
    except KeyboardInterrupt:
        print("[CANCELED]")
        break

    # we have gotten the info we wanted on the address, so remove it 
    ips.remove(address)

    total_done += 1
    time.sleep(random())


# print info
print("[INFO] COMPLETE")
print("_" * 40)

print("[INFO] Alive addresses:")

for ip in alive_ips:
    print("\t{}".format(ip))