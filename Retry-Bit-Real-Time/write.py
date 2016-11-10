#!/usr/bin/env
from subprocess import call
from scapy.all import *
import binascii 
from time import *





class packets_write:

	def __init__(self,Base_station ='d0:b3:3f:b2:e5:00' ):
		#private member of the class
		self.__BASE_STATION_MAC = Base_station; #would be provided to us by the user
		#object to save all the sniffing packets
		self.__packets=[];
		#different object to distinguish the uplink and downlink packets
		self.__uplink_packets=[];
		self.__downlink_packets=[];
		#counters to count the type of packet
		self.__radioUplinkCounter=0;
		self.__radioDownlinkCounter=0;
		self.__TCPUplinkCounter=0;
		self.__TCPDownlinkCounter=0;
		self.__IPUplinkCounter=0;
		self.__IPDownlinkCounter=0;
		 #the averaging limit of the packets for each type is defined in there
		self.__limitTCPUplink=100;
		self.__limitTCPDownlink=100;
		self.__limitIPUplink=100;
		self.__limitIPDownlink=100;
		self.__limitRadioDownlink=100;
		self.__limitRadiUplink=100;
		
		return;

	def getPacket(self): return(self.__packets);

	def allowTCP(self):
		if ((self.__TCPDownlinkCounter >= self.__limitTCPDownlink) and (self.__TCPUplinkCounter >= self.__limitTCPUplink)):
			return True;
		else:
			return False;

	def allowIP(self):
		if((self.__IPDownlinkCounter >= self.__limitIPDownlink) and (self.__IPUplinkCounter >= self.__limitIPUplink)):
			return True;
		else:
			return False;

	def allowRadio(self):
		if((self.__radioDownlinkCounter >= self.__limitRadioDownlink) and (self.__radioUplinkCounter >= self.__limitRadiUplink)):
			return True;
		else:
			return False;

		
	def setTCPUplimit(self,limit):
		self.__limitTCPUplink = limit;	
		return;

	def setTCPDownlimit(self,limit):
		self.__limitTCPDownlink = limit;
		return;

	def setIPDownlimit(self,limit):
		self.__limitIPDownlink = limit;
		return;

	def setIPUplimit(self,limit):
		self.__limitIPUplink = limit;
		return;

	def setRadioDownlimit(self,limit):
		self.__limitRadioDownlink = limit;
		return;

	def setRadioUplimit(self,limit):
		self.__limitRadiUplink = limit;
		return;

	def setBaseStation(self,base = 'd0:b3:3f:b2:e5:00'):
		self.__BASE_STATION_MAC = base;
		return;

	def incrementTCPUplink(self):
		self.__TCPUplinkCounter= self.__TCPUplinkCounter+1;
		return;
	def incrementTCPDownlink(self):
		self.__TCPDownlinkCounter=self.__TCPUplinkCounter+1;
		return;	

	def incrementIPUplink(self):
		self.__IPUplinkCounter=self.__IPUplinkCounter+1;
		return;
	def incrementIPDownlink(self):
		self.__IPDownlinkCounter=self.__IPDownlinkCounter+1;
		return;

	def incrementRadioUplink(self):
		self.__radioUplinkCounter=self.__radioUplinkCounter+1;
		return;
	def incrementRadioDownlink(self):
		self.__radioDownlinkCounter=self.__radioDownlinkCounter+1;
		return;


	def extractPackets(self,number = 10000):
		#add the functionality of monitor mode on and using it;
		call(["sudo","ifconfig","wlan0","down"]);
		call(["sudo","iwconfig","wlan0","mode","Monitor"]);
		call(["sudo","ifconfig","wlan0","up"]);
		call(["sudo","iwconfig","wlan0"]);
		print("Going in Monitor Mode");	
		# Start the sniffing of the packets in the Monitor and promiscious mode
		packets = sniff(timeout = 20, count = 10000);

		call(["sudo","ifconfig","wlan0","down"]);
		call(["sudo","iwconfig","wlan0","mode","Managed"]);
		call(["sudo","ifconfig","wlan0","up"]);
		call(["sudo","iwconfig","wlan0"]);
		print("Going in Managed Mode");
		sleep(15);
		

		self.__packets = packets;
	#	self.__packets = rdpcap('../Wire1.pcap');
		#pacekts = sniff(count = number);
		return;		
	def arrangePackets(self):

		#scapy uses Dot11 header fields add2 and add1 to represent transmitter and reciever MACs repectively
		#for control packets with CTS command the transmitter MAC is not known thatwhy we apply the condition on 			the recieveing MAC
		print(len(self.__packets));
		for i in range(0,len(self.__packets)):
			if(self.__packets[i][Dot11].addr1 == self.__BASE_STATION_MAC):
				self.__uplink_packets.extend(self.__packets[i]);
				if self.__packets[i].haslayer(TCP):
					self.incrementTCPUplink();
				if self.__packets[i].haslayer(IP):
					self.incrementIPUplink();
				if self.__packets[i].haslayer(Dot11):
					self.incrementRadioUplink();

			else:
				self.__downlink_packets.extend(self.__packets[i]);
				if self.__packets[i].haslayer(TCP):
					self.incrementTCPDownlink();
				if self.__packets[i].haslayer(IP):
					self.incrementIPDownlink();
				if self.__packets[i].haslayer(Dot11):
					self.incrementRadioDownlink();			
		return;
	
	def writePackets(self):
		print(len(self.__uplink_packets));
		print(len(self.__downlink_packets));
		if len(self.__uplink_packets) > 0:
			wrpcap('uplink.pcap',self.__uplink_packets);
		if len(self.__downlink_packets) > 0:
			wrpcap('downlink.pcap',self.__downlink_packets);				
		return;


