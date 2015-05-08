#! /usr/bin/python
# (c) 2015 Veit Hailperin
# PoC Network Layout Information Gathering with TCP timestamps

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import xml.sax
import sys
from colorama import init, Fore
# There might be better values in different scenarios. Feel free to play with the value
MAX_DIFFERENCE = 1000


def validate_ip(ip):
    a = ip.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

class NmapHandler(xml.sax.ContentHandler):
    """parses an nmap xml output"""
    def __init__(self):
        self.host = "0.0.0.0"
        self.open_ports = []
        self.port = 0


    def startElement(self, name, attrs):
        if name == "address":
            ip = attrs.getValue("addr")
            if validate_ip(ip):
                self.host = ip
        if name == "port":
            self.port = attrs.getValue("portid")
        if name == "state":
            if attrs.getValue("state") == "open":
                self.open_ports.append(int(self.port))
    def endElement(self, name):
        if name == "port":
            self.port = 0
    

def banner():
    """ banner() - prints banner """
    print ""
    print ".___             __  .__  _____                .__                    __                          "
print "|__| __| _/____   _____/  |_|__|/ ____\__.__.         |  |__   ____  _______/  |_  ______  ______ ___.__."
print "|  |/ __ |/ __ \ /    \   __\  \   __<   |  |  ______ |  |  \ /  _ \/  ___/\   __\/  ___/  \____ <   |  |"
print "|  / /_/ \  ___/|   |  \  | |  ||  |  \___  | /_____/ |   Y  (  <_> )___ \  |  |  \___ \   |  |_> >___  |"
print "|__\____ |\___  >___|  /__| |__||__|  / ____|         |___|  /\____/____  > |__| /____  > /\   __// ____|"
print "        \/    \/     \/               \/                   \/           \/            \/  \/__|   \/     "
print ""

def usage():
    """ usage() - print usage """
    print "Usage: python identify-hosts.py nmap-output.xml"
    print "Note: Nmap file is expected to contain a single host"

def __main__():
    """ main() - runs identify-hosts.py """
    print "This is a PoC script"
    print "(c) 2015 Veit Hailperin\n"
    init()
    if len(sys.argv) != 2:
        usage()
        exit()
    nmap_file = sys.argv[1]
    parser = xml.sax.make_parser()
    r_handler = NmapHandler()
    parser.setContentHandler(r_handler)
    try:
        parser.parse(open(nmap_file, "r"))
    except IOError:
        print "Couldn't open nmap xml file: "+nmap_file+"\n"
        exit(1)
    target = r_handler.host
    hosts = []
    open_ports = r_handler.open_ports
    timestamps = {} # {portnr:[timestamps]}


    for port in open_ports:
        timestamps[port] = []
        counter = 0
        while counter < 5:
            packet = sr1(IP(dst=target)/TCP(dport=port,flags="S",options=[('Timestamp',(0,0))]), verbose=False)
            timestamp = packet[TCP].options[3][1][0]
            timestamps[port].append(timestamp)
            counter += 1

    while len(open_ports) > 0: 
        c_port = open_ports.pop()
        hosts.append([str(c_port)+" ["+str(timestamps[c_port][0])+"]"])
        for port in open_ports:
            if abs(timestamps[port][0] - timestamps[c_port][0]) < MAX_DIFFERENCE:
                hosts[len(hosts)-1].append(str(port)+" ["+str(timestamps[port][0])+"]")
                open_ports.remove(port)

    print "The following ports seem to belong to the same host:"
    i = 1
    for host in hosts:
        print('\033[31m'+ "Host "+str(i)+":"+'\033[32m')
        print(", ".join([str(x) for x in host]))
        print ""
        i += 1
                
__main__()
