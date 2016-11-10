#!/usr/bin/env
from write import *
from ICMP import *
from Radio import *
from myTCP import *
import threading
import time
import urllib2, urllib



#this class is the manager class it is used to manage the extraction of parameters and the sending of data to the 
#server when the extraction is completed. 

#in future it would also have the functionality to control the mobility of the rasberry pi
class ManagerWireless:
	def __init__(self):
		#initialize instance of each class
		self.__packets = packets_write();
		self.__radio = Radio();
		self.__icmp = MyICMP();
		self.__tcp = myTCP();
		self.initiateExtraction();
		
		



	def updateFiles(self):
		#start writing the packets
		self.__packets.extractPackets();
		self.__packets.arrangePackets();
		self.__packets.writePackets();



	def retryParameters(self,times):
		i=0
		while(i<times):
			i+=1;
			t=[];
			if(self.__icmp.getError() == 1):
				t.append(threading.Thread(target=self.__icmp.callPing()))
				t.append(threading.Thread(target=self.__tcp.findHandShake))
			else:
				t.append(threading.Thread(target=self.__tcp.retryHandShake))
			for thread in t:
				thread.daemon = True
				thread.start()
				thread.join();
			#delete all elements of t
			del t[:];
			if(self.__packets.allowTCP()):
				print("Contain TCP packets");
			#extract the throughput of the uplink and downlink stream
			if self.__tcp.getError() == 0 & self.__packets.allowTCP():
				t.append(threading.Thread(target=self.__tcp.calTCPDownlinkThroughput))
				t.append(threading.Thread(target=self.__tcp.calTCPUplinkThroughtput))

				for thread in t:
					thread.daemon = True
					thread.start();
					thread.join();

				return;
			else:
				time.sleep(2);


	def initiateExtraction(self):

		self.updateFiles();
		#parallel processing of the parameter extraction from different layers
		t=[];
		t.append(threading.Thread(target=self.__radio.uplink))
		t.append(threading.Thread(target=self.__radio.downlink))
		t.append(threading.Thread(target=self.__icmp.callPing))
		t.append(threading.Thread(target=self.__tcp.findHandShake))

		for thread in t:
			thread.daemon = True
			thread.start()
			thread.join();
		#delete all elements of t
		del t[:];
		
		#extract the throughput of the uplink and downlink stream
		if self.__tcp.getError() == 0:
			t.append(threading.Thread(target=self.__tcp.calTCPDownlinkThroughput))
			t.append(threading.Thread(target=self.__tcp.calTCPUplinkThroughtput))

			for thread in t:
				thread.daemon = True
				thread.start();
				thread.join();
		else:
			#try extraction of ICMP and TCP parameters after some time
			time.sleep(10);
			self.retryParameters(3); #the argument shows how much time the process is to be repeated
		self.sendParameters();

	def sendParameters(self):
		controlFrame = (float) (self.__radio.getControlFrame()/len(self.__packets.getPacket()))*100;
		managementFrame = (float) (self.__radio.getManagementFrame()/len(self.__packets.getPacket()))*100;
		dataFrame = (float) (self.__radio.getDataFrame()/len(self.__packets.getPacket()))*100;
		if self.__tcp.getError() == 0:
			POSTPacket = {'Rufs': self.__radio.getUplinkFrameSize(),'Rdfs': self.__radio.getDownlinkFrameSize(),
							'Rurr':self.__radio.getUplinkRetransmission(),'Rdrr': self.__radio.getDownlinkRetransmission(),
							'Russ':self.__radio.getUplinkSignalStrength(),'Rdss':self.__radio.getDownlinkSignalStrength(),
							'Irtt': self.__icmp.getroundTripTime(),'Isr': self.__icmp.getSuccessRate(),
							'Ths': self.__tcp.getTCPHandshakeTime(),'Tut': self.__tcp.getTCPUplinkThroughput(),
							'Tdt': self.__tcp.getTCPDownlinkThroughput(),'Turr': self.__tcp.getTCPUplinkRetransmissionRate(),
							'Tdrr': self.__tcp.getTCPDownlinkRetransmissionRate(),'Rcf':controlFrame,'Rmf':managementFrame,'Rdf':dataFrame, 'auth': 101,'device':1};
		else:
			if self.__icmp.getError() == 1:
				POSTPacket = {'Rufs': self.__radio.getUplinkFrameSize(),'Rdfs': self.__radio.getDownlinkFrameSize(),
							'Rurr':self.__radio.getUplinkRetransmission(),'Rdrr': self.__radio.getDownlinkRetransmission(),
							'Russ':self.__radio.getUplinkSignalStrength(),'Rdss':self.__radio.getDownlinkSignalStrength(),
							'Irtt': -1,'Isr': -1,
							'Ths': -1,'Tut': -1,
							'Tdt': -1,'Turr': self.__tcp.getTCPUplinkRetransmissionRate(),
							'Tdrr': self.__tcp.getTCPDownlinkRetransmissionRate(),'auth': 102,'device':1};
			else:
				POSTPacket = {'Rufs': self.__radio.getUplinkFrameSize(),'Rdfs': self.__radio.getDownlinkFrameSize(),
							'Rurr':self.__radio.getUplinkRetransmission(),'Rdrr': self.__radio.getDownlinkRetransmission(),
							'Russ':self.__radio.getUplinkSignalStrength(),'Rdss':self.__radio.getDownlinkSignalStrength(),
							'Irtt': self.__icmp.getroundTripTime(),'Isr': self.__icmp.getSuccessRate(),
							'Ths': -1,'Tut': -1,
							'Tdt': -1,'Turr': self.__tcp.getTCPUplinkRetransmissionRate(),
							'Tdrr': self.__tcp.getTCPDownlinkRetransmissionRate(),'auth':103,'device':1};

		print(POSTPacket);
		POSTData = urllib.urlencode(POSTPacket);
		path='http://www.galaxyinstitute.pk/wipi/recieve.php'    #the url you want to POST to
		req=urllib2.Request(path, POSTData)
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		page=urllib2.urlopen(req).read()
		print page		




