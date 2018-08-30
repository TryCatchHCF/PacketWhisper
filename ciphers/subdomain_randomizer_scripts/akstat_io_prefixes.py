#!/usr/bin/python
# 
# Filename:  akstat_io_prefixes.py
#
# Version: 1.0.0
#
# Author:  Joe Gervais (TryCatchHCF)
#
# Summary:  Appends or removes random 4-char string of [a-z,0-9] plus 
# ".akstat.io" to each line of a file that's been Cloakified using 
# akstat_prefixes cipher.
#
# Description:  
#

import os, sys, getopt, random

gCharList = "abcdefghijklmnopqrstuvwxyz0123456789"

if ( len(sys.argv) != 2 ):

	print "usage: akstat_io_prefixes.py <cloakedFilename>"
	print
	exit

else:

    with open( sys.argv[1], "r" ) as file:

            cloakedFile = file.read().splitlines()

    with open( sys.argv[1], "w" ) as file:

        for i in cloakedFile:
            
            count = 0
            subdomainNoise = ""

            while ( count < 4 ):
                subdomainNoise = subdomainNoise + gCharList[ (random.randint(0,35)) ]
                count = count + 1
                    
            subdomainNoise = subdomainNoise + ".akstat.io"

            file.write( i + subdomainNoise + "\n" )

