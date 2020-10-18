# this is a really slow network scanner. 
# the idea is that it will slowly poke around and check who's up and whos not
# over the course of a while, ideally without being discoverd or tripping over 
# network detection systems. who knows if it works

import socket as s
import netifaces
import netaddr
import time
import sys
import os
from random import randint, random
from signal import signal, SIGINT

# some random ports to try to connect to while working
random_ports = [80, 443, 8080, 22]

# log file object
log_f = None

# global list of current ips
ips = []
alive_ips = []

# logs some stuff to stdout and log.txt
def log(string):
    global log_f
    if log_f == None:
        log_f = open('log.txt', 'w')
    
    log_f.write(string)
    print(string)

# CTRL-C handler
def sig_handler(signal_recvd, frame):
    global alive_ips
    global ips

    print("[INFO] Caught CTRL-C. Halting...")

    f = open(".resume", "w")

    for ip in ips:
        f.write(ip)
        f.write("\n")
    f.close()

    complete()

    sys.exit(1)

# cleans the resume file
def clear_resume():
    os.remove(".resume")

# done with scanning (either quit or completion)
def complete():
    global alive_ips

    # print info
    log("[INFO] COMPLETE")
    log("_" * 40)

    print("[INFO] Alive addresses:")

    for ip in alive_ips:
        print("\t{}".format(ip))


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


# main function
def main(interface):
    global ips
    global alive_ips

    # check if stuff has already been run
    if os.path.exists(".resume"):
        cont = input("[INFO] Detected previously incomplete run\n\tContinue? (y/n) > ").lower()
        if cont == 'n':
            # generate a new set
            ips = generate_targets(interface)
        else:
            print("[INFO] Resuming scan...")
            # read in the old data
            f = open(".resume", "r")
            dat = f.read()
            ips = dat.replace("\00", "").splitlines()[0:-1]
            f.close()
            print("[INFO] Remaining addresses: {}".format(len(ips)))
            
    else:
        ips = generate_targets(interface)



    # set up the terminating signal handler
    signal(SIGINT, sig_handler)
    
    sock = s.socket(s.AF_INET, s.SOCK_STREAM)
    #sock.setsockopt()

    num_ips = len(ips)
    total_done = 0

    # loop over the addresses
    for i in range(num_ips):
        # randomly choose an ip from the list
        address = ips[randint(0, len(ips)-1)]
        # try to connect on random known port
        try:
            port = random_ports[randint(0, len(random_ports)-1)]
            log("[INFO] Trying {} on {} ({:>.1f}%)".format(address, port, total_done/len(ips)))

            sock.connect((address, port))
        
            # what are the chances we get this far without exceptions? 
            # low... but not impossible
            sock.close()
            alive_ips.append(address)
            log("[INFO] Address '{}' is up AND port '{}' is open".format(address, port))
    
        # host is up and port is closed
        except ConnectionRefusedError:
            alive_ips.append(address)
            log("[INFO] Address '{}' is up".format(address))

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

    clear_resume()
    complete()




if len(sys.argv) != 2:
    print("[ERROR] Illegal argument count")
    print("Usage: {} <interface>".format(sys.argv[0]))
    sys.exit(1)
else:
    interface = sys.argv[1]


main(interface)