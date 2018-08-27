#!/usr/bin/python
# 
# Filename:  cdn_optimizely_prefixes.py
#
# Version: 1.0.0
#
# Author:  Joe Gervais (TryCatchHCF)
#
# Summary:  Appends or removes random 6-digit string plus ".cdn.optimizely" to
# each line of a file that's been Cloakified using cdn_optimizely_prefixes cipher.
#
# Description:  
#

import os, sys, getopt, random


if ( len(sys.argv) != 3 ):

	print "usage: cdn_optimizely_prefixes.py <cloakedFilename> <True/False>"
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

				while ( count < 4 ):
					subdomainNoise = subdomainNoise + str( random.randint(0,9))
					count = count + 1

				subdomainNoise = subdomainNoise + ".cdn.optimizely.com"

				file.write( i + subdomainNoise + "\n" )

	elif ( sys.argv[ 2 ] == "False" ):

		with open( sys.argv[1], "r" ) as file:

    			cloakedFile = file.readlines()

		with open( sys.argv[1], "w" ) as file:

			for i in cloakedFile:
				print i[:5]
	
	else:
		print ""
		print "Invalid option:", sys.argv[ 2 ]

