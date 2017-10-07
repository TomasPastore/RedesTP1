#!/usr/bin/env python

from scapy.all import *

packets = sniff( iface = "wlo1")
wrpcap('sniffed_countLibre.pcap', packets)