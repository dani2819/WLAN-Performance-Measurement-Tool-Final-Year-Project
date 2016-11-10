#!/usr/bin/env
from ManagerWireless import *

#########with threading##############

manage = ManagerWireless();




###############without threading###############################\
#####used for the comparision of the two ##############
#packets = packets_write();
#packets.extractPackets();
##packets.arrangePackets();
#packets.writePackets();

#radio = Radio();
#radio.uplink();
#radio.downlink();

#icmp = MyICMP();
#icmp.callPing();
#if icmp.getError():
#	print("Error in IMCP paramter");
#else:
#	print("Success Rate:", str(icmp.getSuccessRate()));
#	print("Round Trip Time:", str(icmp.getroundTripTime()));

#	tcp = myTCP(icmp.getBaseIP());
#	tcp.findHandShake();

#	print("TCP Handshake time: ", tcp.getTCPHandshakeTime());
#	if tcp.getError() == 0:
#		tcp.calTCPDownlinkThroughput();
		#tcp.calTCPUplinkThroughtput();

