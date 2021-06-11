# this is a really slow network scanner.
# the idea is that it will slowly poke around and check who's up and whos not
# over the course of a while, ideally without being discoverd or tripping over
# network detection systems. who knows if it works

import socket as s
import netifaces
import arprequest
import argparse
import netaddr
import time
import sys
import os
import common
from random import randint, random
from signal import signal, SIGINT


# set up arguments
parser = argparse.ArgumentParser(description="Slow network scanner")
parser.add_argument('-i', "--interface", metavar="<INTERFACE>", type=str, help="Interface to use when scanning", required=True)
parser.add_argument('-a', "--arp", dest="arpscan", action="store_true", help="Utilize ARP scanning instead of TCP connections")
parser.set_defaults(arpscan=False)


# some random ports to try to connect to while working
random_ports = [80, 443, 8080, 22]

# log file object
log_f = None

# global list of current ips
ips = []
alive_ips = []

# logs some stuff to stdout and log.txt
def log(string, e="\n"):
    global log_f
    if log_f == None:
        log_f = open('log.txt', 'w')

    log_f.write(string)
    print(string, end=e)

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
def run(interface, scantype=0):
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
    num_ips = len(ips)
    total_done = 0


    # normal TCP scan type
    if scantype == 0:
        sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        #sock.setsockopt()

        
        # loop over the addresses
        for i in range(num_ips):
            # randomly choose an ip from the list
            address = ips[randint(0, len(ips)-1)]
            # try to connect on random known port
            try:
                port = random_ports[randint(0, len(random_ports)-1)]
                log("[INFO] Trying {} on {} ({:>.1f}%)".format(address, port, total_done/len(ips)), e="\r")

                sock.connect((address, port))

                # what are the chances we get this far without exceptions?
                # low... but not impossible
                sock.close()
                alive_ips.append(address)
                log("[INFO] Address '{}' is up AND port '{}' is open".format(address, port))

            # host is up and port is closed
            except ConnectionRefusedError:
                alive_ips.append(address)
                log("[INFO] Address '{}' is up                ".format(address))

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

    # ARP IP scan
    elif scantype == 1:
        for i in range(num_ips):

            # choose an address
            address = ips[randint(0, len(ips)-1)]
            log("[INFO] Trying {} ({:>.1f}%)".format(address, total_done/len(ips)), e="\r")
            
            # create request
            alive = arprequest.ArpRequest(address, interface)
            if alive.request():
                alive_ips.append(address)
                log("[INFO] Address '{}' is up                ".format(address))

            # move on
            ips.remove(address)
            total_done += 1
            time.sleep(random())



    clear_resume()
    complete()



def main():
    # check privilages
    if not common.has_root():
        print("[ERROR] Insufficient privilages! Please run as root")
        sys.exit(1)

    args = parser.parse_args()
    scantype = 0
    interface = args.interface

    # see if we are scanning using ARP
    if args.arpscan:
        scantype = 1


    run(interface, scantype=1)


if __name__ == '__main__':
    main()