#!/usr/bin/python
from scapy.all import *
import time
import math


_myIP = "193.168.1.11";
_SYNCflag = "2";
_SYNC_ACK_flag = "18";
_RETRANSMIT_flag = 8;



TCPpackets=0.0;
TCPRetransmitPackets=0.0;
RTT_time=3.0;
_upMSS=0.0;
_downMSS=0.0;


#start_time=time.time();
#ans,unans=sr( IP(dst="172.16.0.254")/TCP(dport=80,flags="S") );
#finish_time=time.time();


#if ans:
	#ans.summary();
	#print "The TCP RTT Time is: ",finish_time - start_time;
	#RTT_time = finish_time - start_time;
#else:
	#unans.summary();


packets = rdpcap('802TCP.pcap')
for i in range (0,len(packets)):
	if packets[i].haslayer(TCP):
		TCPpackets = TCPpackets+1;
		sourceIP = packets[i][IP].src;
		destIP = packets[i][IP].dst;
		#print(sourceIP);
		#extraction of upstream MSS
		if str(sourceIP) == _myIP and str(packets[i][TCP].flags) == _SYNCflag:
			print i+1;
			_upMSS = packets[i][TCP].options[0][1];
			print "Upstream MSS ==>", _upMSS;
		
		#extraction of downstream MSS
		elif str(destIP) == _myIP and str(packets[i][TCP].flags) == _SYNC_ACK_flag:
			print i+1;
			_downMSS = packets[i][TCP].options[0][1];
			print "Downstream MSS ==>", packets[i][TCP].options[0][1];	
		
		pacRetransmit = packets[i][Dot11].FCfield;
		if (pacRetransmit & _RETRANSMIT_flag == _RETRANSMIT_flag):
			TCPRetransmitPackets = TCPRetransmitPackets+1;
			
	print("Is it working??!!!");
retransmitRate = TCPRetransmitPackets/TCPpackets;
#print(_upMSS);
#print(_downMSS);
Upstream_Throughput = (_upMSS*1.22)/(RTT_time * float(math.sqrt(retransmitRate)));
Downstream_Throughput = (_downMSS*1.22)/(RTT_time* float(math.sqrt(retransmitRate)));
 
print "The TCP Retransmission Rate is ==>" + str(retransmitRate*100) + "%" ;
print "Up stream Throughput is ==>", Upstream_Throughput;
print "Down stream Throughput is ==>", Downstream_Throughput;
