#!/usr/bin/python
from scapy.all import *
import time
from multiprocessing import Process, Queue
from threading import Thread
from ICMP import *
import math
from random import randint; 

#Have to test the throughtput part
#the file name is changed to 802TCP in downlink throughput method
class myTCP:
	def __init__(self,destIP='192.168.1.1'):
		self.__TCPHandshakeTime=0.000000009;
		self.__TCPUplinkThroughput=0.0;
		self.__TCPDownlinkThroughput=0.0;

		self.__TCPRetranmissionRate=0.0;
		self.__TCPuplinkRetransmission=0.0;
		self.__TCPdownlinkRetransmission=0.0;

		self.__TCPPackets=0;
		
		self.__BaseIP = destIP;
		self.__IPerror=0;
		self.__HSerror=0;
		

	def getTCPHandshakeTime(self): return self.__TCPHandshakeTime;
	def getTCPUplinkThroughput(self): return self.__TCPUplinkThroughput;
	def getTCPDownlinkThroughput(self): return self.__TCPDownlinkThroughput;
	def getTCPUplinkRetransmissionRate(self): return self.__TCPuplinkRetransmission;
	def getTCPDownlinkRetransmissionRate(self): return self.__TCPdownlinkRetransmission;
	def getError(self): return self.__HSerror ==1 | self.__IPerror == 1;
	def getHSDone(self): return self.__HSDone;
	# as a default TCP parameters would be extracted after ICMP parameters so the default IP would be give to it by the ICMP parameters
	# however if there is any need for independent calling of the TCP parameters than this function would be used
	def setBaseIP(self):
		icmp = MyICMP();
		icmp.generateOutput();
		if icmp.getError():
			self.__IPerror = 1;
			return;
		else:
			self.__BaseIP = icmp.getBaseIP();
			print "Defaulf IP is: " + self.__BaseIP;
		return;

	def TCPHandShake(self,):
		sequence=randint(0,40000); # generate random number
		ports=[1500,80,20,7,115];
		desPort=ports[randint(0,len(ports)-1)];
		srcPort=ports[randint(0,len(ports)-1)];
		HandShakeTime =0.00009;
		#sends sync patcket to the server
		ip=IP(dst=self.__BaseIP)
		TCP_SYN=TCP(sport=srcPort, dport=desPort, flags="S", seq=sequence)
		#start the timer
		start_time = time.time();

		TCP_SYNACK=sr1(ip/TCP_SYN)
		
		#if(TCP_SYNACK == null):
		#	self.__HSerror = 1;
		#	return;
		my_ack = TCP_SYNACK.seq + 1
		TCP_ACK=TCP(sport=srcPort, dport=desPort, flags="A", seq=sequence+1, ack=my_ack)
		send(ip/TCP_ACK)
		#end the timer
		finish_time = time.time();		
		self.__TCPHandshakeTime =  finish_time - start_time;
		
		payload = "Packet sent successful";
		TCP_PUSH = TCP(sport = srcPort, dport=desPort, flags="PA", seq = sequence+2, ack=my_ack);
		send(ip/TCP_PUSH/payload);
		HandShakeTime = finish_time - start_time;

		write = open("TCPparameters.txt","w");
		write.write(str(HandShakeTime) + "\n");
		write.write("0");
		write.close();



	def setDefaultTCPParamters(self):
		write = open("TCPparameters.txt","w");
		write.write("0.0009\n");
		write.write("1");
		write.close();

	def readTCPParameters(self):
		read = open("TCPparameters.txt", "r");
		result = read.readlines();
		s="";
		res=[];
		line = result[0];
		for i in range(0,len(line)):
			if line[i] != "\n":
				s += line[i];
		res.append(float(s));
		res.append(int(result[1]));
		return res;			

	def findHandShake(self):
		
		self.setBaseIP();
		self.setDefaultTCPParamters()
		if self.__IPerror != 1:
			#multiprocessing is used to stop the program if the tcp handshake is not successful
			#p = Process(target=self.TCPHandShake, name="TCPHandShake",args=(q,))
			p = Process(target=self.TCPHandShake, name="TCPHandShake");
		    	p.start()
			
		
			p.join(5);
			tcpResults = self.readTCPParameters();
			self.__TCPHandshakeTime = tcpResults[0];
			self.__HSerror = tcpResults[1];
			print self.__TCPHandshakeTime;
			print self.__HSerror;
			
			# If thread is active
			if p.is_alive():
			    self.__HSerror = 1;
			    print ("Not successful");
				# Terminate process
			    p.terminate()
			    p.join()

		else:
			print "cannot find IP";


	def retryHandShake(self):
		
		self.setDefaultTCPParamters()
		if self.__IPerror != 1:
			#multiprocessing is used to stop the program if the tcp handshake is not successful
			#p = Process(target=self.TCPHandShake, name="TCPHandShake",args=(q,))
			p = Process(target=self.TCPHandShake, name="TCPHandShake");
		    	p.start()
			
		
			p.join(5);
			tcpResults = self.readTCPParameters();
			self.__TCPHandshakeTime = tcpResults[0];
			self.__HSerror = tcpResults[1];
			print self.__TCPHandshakeTime;
			print self.__HSerror;
			
			# If thread is active
			if p.is_alive():
			    self.__HSerror = 1;
			    print ("Not successful");
				# Terminate process
			    p.terminate()
			    p.join()

		else:
			print "cannot find IP";


		

	def calTCPUplinkThroughtput(self):
		packets = rdpcap('uplink.pcap');
		uplinkPackets=0;
		upMSS = 0.0;
		MMSPacketCount=0;
		SYNCflag = "2";
		SYNC_ACK_flag = "18";
		RETRANSMIT_flag = 8;

		for i in range (0,len(packets)):
			if packets[i].haslayer(TCP):
				uplinkPackets = uplinkPackets +1;
				sourceIP = packets[i][IP].src;
				#extraction of upstream MSS
				if str(sourceIP) == self.__BaseIP and str(packets[i][TCP].flags) == SYNCflag:
					
					upMSS = upMSS + packets[i][TCP].options[0][1];
					MMSPacketCount= MSSpacketCount + 1;
	
				pacRetransmit = packets[i][Dot11].FCfield;
				if (pacRetransmit & RETRANSMIT_flag == RETRANSMIT_flag):
							self.__TCPuplinkRetransmission = self.__TCPuplinkRetransmission +1;

		#convert packet counts into rate
		if uplinkPackets > 0:
			self.__TCPuplinkRetransmission = self.__TCPuplinkRetransmission/uplinkPackets;
		if upMSS != 0.0 and self.__TCPuplinkRetransmission:
			upMSS = upMSS/MSSpacketCount;
			self.__TCPUplinkThroughput = (upMSS*1.22)/(self.__TCPHandshakeTime * float(math.sqrt(self.__TCPuplinkRetransmission)));
		print(upMSS);
		print(self.__TCPuplinkRetransmission);
		print(self.__TCPUplinkThroughput);

	def calTCPDownlinkThroughput(self):
		packets = rdpcap('downlink.pcap');
		downlinkPackets=0;
		MMSPacketCount=0;
		downMSS = 0.0;
		SYNCflag = "2";
		SYNC_ACK_flag = "18";
		RETRANSMIT_flag = 8;

		for i in range (0,len(packets)):
			if packets[i].haslayer(TCP):
				
				destIP = packets[i][IP].dst;
				#extraction of downstream MSS
				downlinkPackets  = downlinkPackets +1;
				if str(destIP) == self.__BaseIP and str(packets[i][TCP].flags) == SYNC_ACK_flag:
					
					downMSS = downMSS + packets[i][TCP].options[0][1];
					MSSpacketCount = MSSpacketCount +1;
	
				pacRetransmit = packets[i][Dot11].FCfield;
				if (pacRetransmit & RETRANSMIT_flag == RETRANSMIT_flag):
							self.__TCPdownlinkRetransmission = self.__TCPdownlinkRetransmission +1;

		#convert packet counts into rate
		if self.__TCPdownlinkRetransmission != 0.0:
			self.__TCPdownlinkRetransmission = self.__TCPdownlinkRetransmission/downlinkPackets;
		if downMSS != 0.0:
			downMSS = downMSS/downlinkPackets;
			self.__TCPDownlinkThroughput = (downMSS*1.22)/(self.__TCPHandshakeTime * float(math.sqrt(self.__TCPdownlinkRetransmission)));

