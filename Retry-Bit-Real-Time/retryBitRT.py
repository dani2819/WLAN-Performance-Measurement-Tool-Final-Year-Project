#!/usr/bin/env
from subprocess import call
from scapy.all import *
import binascii
import struct
import datetime
import csv


# This function is used to update the file.
# This log file is a csv file which would contain
# paramters and would be used for the analysis purpose
#############################################################################################################
#############################################################################################################
def writeFile(packetLen,transmissionRate):

	with open('eggs.csv', 'a') as csvfile:
    		spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
    		spamwriter.writerow([datetime.datetime.now()] )
    		spamwriter.writerow([str(packetLen),str(transmissionRate)] )
##############################################################################################################
##############################################################################################################



for j in range(0,3):
	# These are the OS commands which are used to set on the Monitor mode for the WIFI adapter
	call(["sudo","ifconfig","wlan0","down"]);
	call(["sudo","iwconfig","wlan0","mode","Monitor"]);
	call(["sudo","ifconfig","wlan0","up"]);
	
	# Start the sniffing of the packets in the Monitor and promiscious mode
	packets = sniff(count = 2000);

	#mask used to extract the retry bit
	retransmitMask = binascii.unhexlify("08");
	retransmission = 0;

	
	for i in range(0,len(packet)):
		#Extract Dot11 header and the other packet
		pac = str(packets[i][Dot11])
		print(pac);

		#Enter only if the retry bit is 1
		if ((ord(pac[1]) & ord(retransmitMask)) == 8):
			print("Packet: " + str(i));
			print(hexdump(packets[i][Dot11]));	#HEX dump to check for the retry bit
			#print("The retransmission bit is: " + str((ord(pac[1]) & ord(retransmitMask))));
			retransmission = retransmission + 1; # increment the number of retransmitted packets

	# write the result to the csv file
	writeFile(len(packets),float(retransmission)/(len(packets)))

	

