#!/usr/bin/env python3

import pyshark

def listen_for_activity(addr):
    cap = pyshark.LiveCapture(interface="wlp3s0")
    print("Waiting for activity from %s..." % addr)
    for packet in cap.sniff_continuously():
        if "Layer IP:" in str(packet):

            tmp_str = str(packet).split("Layer IP:")[-1].splitlines()
            tgt_line = ""
            for line in tmp_str:
                if "Source: " in line:
                    tgt_line = line
                    break
            test_addr = tgt_line.split(" ")[-1]

            if test_addr == addr:
                print("Found activity from %s!" % addr)
                packet.pretty_print()
                return


def find_active():
    cap = pyshark.LiveCapture(interface="wlp3s0")
    print("Finding active devices...")
    
    active_ips = []
    for packet in cap.sniff_continuously():
        if "Layer IP:" in str(packet):
            tmp_str = str(packet).split("Layer IP:")[-1].splitlines()
            tgt_line = ""
            for line in tmp_str:
                if "Source:" in line:
                    tgt_line = line
                    break
            test_addr = tgt_line.split(" ")[-1]

            if test_addr not in active_ips:
                print("New IP: %s" % test_addr)
                active_ips.append(test_addr)

def scan_net():
    cap = pyshark.LiveCapture(interface="wlp3s0")
    print("Capturing...")
    for packet in cap.sniff_continuously(packet_count=5):
        print("Packet: ", packet)
    print("Sniffed packets")

#scan_net()
#listen_for_activity("192.168.0.22")

find_active()
