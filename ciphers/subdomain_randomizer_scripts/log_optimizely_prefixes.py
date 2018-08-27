#!/usr/bin/python
# 
# Filename:  log_optimizely_prefixes.py
#
# Version: 1.0.0
#
# Author:  Joe Gervais (TryCatchHCF)
#
# Summary:  Appends or removes random 8-digit string plus ".log.optimizely.com" 
# to each line of a file that's been Cloakified using log_optimizely_prefixes cipher.
#
# Description:  
#

import os, sys, getopt, random

if ( len(sys.argv) != 3 ):

	print "usage: log_optimizely_prefixes.py <cloakedFilename> <True/False>"
	print
	exit

else:

	if ( sys.argv[ 2 ] == "True" ):

		with open( sys.argv[1], "r" ) as file:

    			cloakedFile = file.read().splitlines()

		with open( sys.argv[1], "w" ) as file:

			for i in cloakedFile:

				count = 0
				subdomainNoise = ""

				while ( count < 5 ):
					subdomainNoise = subdomainNoise + str(random.randint(0,9))
					count = count + 1

				subdomainNoise = subdomainNoise + ".log.optimizely.com"

				file.write( i + subdomainNoise + "\n" )

	elif ( sys.argv[ 2 ] == "False" ):

		with open( sys.argv[1], "r" ) as file:

    			cloakedFile = file.readlines()

		with open( sys.argv[1], "w" ) as file:

			for i in cloakedFile:
				print i[:6]
	
	else:
		print ""
		print "Invalid option:", sys.argv[ 2 ]
