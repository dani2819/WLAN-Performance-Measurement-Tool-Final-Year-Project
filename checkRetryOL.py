
#!/usr/bin/env
from subprocess import call
from scapy.all import *
import binascii
import struct
import datetime
import csv


# Start the sniffing of the packets in the Monitor and promiscious mode
packets = rdpcap('Wire1.pcap')

#mask used to extract the retry bit
retransmitMask = binascii.unhexlify("08");
retransmission = 0;

for i in range(0,1000):
	#Extract Dot11 header and the other packet
	pac = str(packets[i][Dot11])
	#Enter only if the retry bit is 1
	if ((ord(pac[1]) & ord(retransmitMask)) == 8):
		print("Packet: " + str(i+1));
		print(hexdump(packets[i][Dot11]));	#HEX dump to check for the retry bit
		#print("The retransmission bit is: " + str((ord(pac[1]) & ord(retransmitMask))));
		retransmission = retransmission + 1; # increment the number of retransmitted packets

