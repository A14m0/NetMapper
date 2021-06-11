#!/usr/bin/env python3

import pyshark
import argparse
import sys

# import common functions
import common

# set up arguments
parser = argparse.ArgumentParser(description="Passively look for devices on your network")
parser.add_argument("--interface", metavar="<INTERFACE>", type=str, help="Interface to use when scanning")
parser.add_argument("--watch", metavar="ADDRESS", type=str, help="Watch for activity from a specific IPv4 address")
parser.add_argument("--watchmac", metavar="MAC", type=str, help="Watch for activity from a specific MAC address")
parser.add_argument("--printall", dest="printall", action='store_true', help="Print every packet we see")
parser.set_defaults(printall=False)

# watch for activity from a particular address
def listen_for_activity(addr, device="wlp58s0", search="Layer IP:"):
    # create capture generator
    cap = pyshark.LiveCapture(interface=device)
    print("Waiting for activity from %s..." % addr)
    addr = addr.lower()

    total_packets = 0
    for packet in cap.sniff_continuously():
        total_packets += 1
        # get all of the IP packets
        if search in str(packet):

            tmp_str = str(packet).split("Layer IP:")[-1].splitlines()
            tgt_line = ""

            # check if the address source is correct
            for line in tmp_str:
                if "Source: " in line:
                    tgt_line = line
                    break

            test_addr = tgt_line.split(" ")[-1]
            
            if test_addr == addr:
                print("Found activity from %s! (checked %d packets)" % (addr, total_packets))
                packet.pretty_print()
                return
        if total_packets%2 == 0:
            print("Checked %d packets" % total_packets, end="\r")

# looks for general activity and prints unique IP addresses
def find_active(device="wlp58s0"):

    # set up the capture object
    cap = pyshark.LiveCapture(interface=device)
    print("Finding active devices...")

    active_ips = []
    total_packets = 0

    # go over packets
    for packet in cap.sniff_continuously():
        if "Layer IP:" in str(packet):
            total_packets += 1
            tmp_str = str(packet).split("Layer IP:")[-1].splitlines()
            tgt_line = ""
            for line in tmp_str:
                if "Source:" in line:
                    tgt_line = line
                    break
            test_addr = tgt_line.split(" ")[-1]

            # check if the packet came from a new source
            if test_addr not in active_ips:
                print("New IP: %s" % test_addr)
                active_ips.append(test_addr)

# literally prints every packet it finds
def scan_net(device="wlp58s0"):
    cap = pyshark.LiveCapture(interface=device)
    print("Capturing...")
    for packet in cap.sniff_continuously():
        print("Packet: ", packet)
    print("Sniffed packets")


# the main function
def main():
    # parse the arguments
    args = parser.parse_args()

    if not common.has_root():
        print("[Error] Insufficient privilages! Please run as root")
        sys.exit(1)

    if args.watch:
        if args.interface:
            listen_for_activity(args.watch, args.interface)
        else:
            listen_for_activity(args.watch)
    elif args.watchmac:
        if args.interface:
            listen_for_activity(args.watchmac, args.interface, "Layer ETH:")
        else:
            listen_for_activity(args.watchmac, search="Layer ETH:")
    elif args.printall:
        if args.interface:
            scan_net(args.interface)
        else:
            scan_net()

    elif args.interface:
        find_active(args.interface)
    else:
        find_active()


if __name__ == "__main__":
    main()
