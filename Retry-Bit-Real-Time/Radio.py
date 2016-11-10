#!/usr/bin/env;

from subprocess import call
from scapy.all import *
import binascii
import struct
import datetime
import csv
import scapy_ex
from math import pow



class Radio:
	def __init__(self):
		#declaring the private members of the class
		self.__uplinkRetransmission=0.0;
		self.__downlinkRetransmission=0.0;
		self.__uplinkFrameSize=0.0;
		self.__donwlinkFrameSize=0.0;
		self.__UplinkcontrolFrame=0.0;
		self.__UplinkmanagementFrame=0.0;
		self.__UplinkdataFrame=0.0;
		self.__DownlinkcontrolFrame=0.0;
		self.__DownlinkmanagementFrame=0.0;
		self.__DownlinkdataFrame=0.0;
		self.__DonwlinkSignalStrength=0.0;
		self.__UplinkSignalStrength=0.0;

		
		#Different types of Dot11 frame sizes
		self.__MANAGEMENT_FRAME_SIZE = 24;
		self.__MANAGEMENT_FRAME_CODE = 0;


		self.__CONTROL_FRAME_CODE = 4;
		self.__CONTROL_BLOCK_ACK_FRAME_SIZE = 32; # with bitmap
		self.__CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE=32;
		self.__CONTROL_CTS_FRAME_SIZE=14;
		self.__CONTROL_ACK_FRAME_SIZE=14;
		self.__CONTROL_RTS_FRAME_SIZE=20;
		self.__CONTROL_CF_END_FRAME_SIZE=20; 		#accoding to PCF Algorithm
		self.__CONTROL_CF_END_ACK_FRAME_SIZE=20;


		self.__DATA_FRAME_CODE = 8;
		self.__DATA_DATA_FRAME_SIZE = 36;	#inspection from wireshark
		self.__DATA_DATA_CF_ACK_FRAME_SIZE = 36;	#cf-ack from PCF algorithm
		self.__DATA_QOS_DATA_FRAME_SIZE=38;


		return;

	#setters and getters
	def getDownlinkSignalStrength(self): return self.__DonwlinkSignalStrength;
	def getUplinkSignalStrength(self): return self.__UplinkSignalStrength;
	def getUplinkRetransmission(self): return self.__uplinkRetransmission;
	def getDownlinkRetransmission(self): return self.__downlinkRetransmission;
	def getUplinkFrameSize(self): return self.__uplinkFrameSize;
	def getDownlinkFrameSize(self): return self.__donwlinkFrameSize;
	def getControlFrame(self): return (self.__UplinkcontrolFrame + self.__DownlinkcontrolFrame);
	def getManagementFrame(self): return (self.__UplinkmanagementFrame + self.__DownlinkmanagementFrame);
	def getDataFrame(self): return (self.__UplinkdataFrame + self.__DownlinkdataFrame);

	def uplink(self):
		packets = rdpcap('uplink.pcap');
		retransmitMask = binascii.unhexlify("08");
		for i in range (0,len(packets)):

			signalStrength = float(packets[i][RadioTap].dBm_AntSignal);
			signalStrength_mW=0.0;
			if signalStrength > 0:
				signalStrength_mW = pow(10,signalStrength/10);
			else:
				signalStrength_mW = 1/(pow(10,abs(signalStrength)/10));

			self.__UplinkSignalStrength = self.__UplinkSignalStrength + signalStrength_mW;

			pac = str(packets[i][Dot11]);
	#Enter only if the retry bit is 1
			if ((ord(pac[1]) & ord(retransmitMask)) == 8):
				#print("The retransmission bit is: " + str((ord(pac[1]) & ord(retransmitMask))));
				self.__uplinkRetransmission = self.__uplinkRetransmission + 1; # increment the number of retransmitted packets
			self.setUplinkFrameSize(str(packets[i][Dot11]));
		#convert the figures into rates
		print(self.__uplinkFrameSize);		
		self.__uplinkFrameSize = self.__uplinkFrameSize/len(packets);
		self.__uplinkRetransmission = self.__uplinkRetransmission/len(packets);
		self.__UplinkSignalStrength = self.__UplinkSignalStrength/len(packets);
		print("uplink Retransmission rate of Radio layer: ", str(self.__uplinkRetransmission));
		print("uplink Avg Frame Size of Radio layer: ",str(self.__uplinkFrameSize));
		return;	

	def downlink(self):
		packets = rdpcap('downlink.pcap');
		retransmitMask = binascii.unhexlify("08");
		for i in range (0,len(packets)):

			signalStrength = float(packets[i][RadioTap].dBm_AntSignal);
			signalStrength_mW=0.0;
			if signalStrength > 0:
				signalStrength_mW = pow(10,signalStrength/10);
			else:
				signalStrength_mW = 1/(pow(10,abs(signalStrength)/10));

			self.__DonwlinkSignalStrength = self.__DonwlinkSignalStrength + signalStrength_mW;
			pac = str(packets[i][Dot11]);
		#Enter only if the retry bit is 1
			if ((ord(pac[1]) & ord(retransmitMask)) == 8):
					#print("The retransmission bit is: " + str((ord(pac[1]) & ord(retransmitMask))));
				self.__downlinkRetransmission = self.__downlinkRetransmission + 1; # increment the number of retransmitted packets
			self.setDownlinkFrameSize(str(packets[i][Dot11]));
			#convert the figures into rates
		self.__donwlinkFrameSize = self.__donwlinkFrameSize/len(packets);
		self.__downlinkRetransmission = self.__downlinkRetransmission/len(packets);
		self.__DonwlinkSignalStrength = self.__DonwlinkSignalStrength/(len(packets));
		print("downlink Retransmission rate of Radio layer: ", str(self.__downlinkRetransmission));
		print("downlink Avg Frame Size of Radio layer: ",str(self.__donwlinkFrameSize));
		return;	



	#Methods defined for the checking of the frame types
	def setUplinkFrameSize(self,pac):
		frameTypeMask = binascii.unhexlify("FC");
		frameTypeMask1 = binascii.unhexlify("0C");
	
		#extract the type and the subtype
		frameBit = ord(pac[0]) & ord(frameTypeMask);
		
		if (ord(pac[0]) & ord(frameTypeMask1) == self.__MANAGEMENT_FRAME_CODE):
			print("Management packet");
			self.__uplinkFrameSize = self.__uplinkFrameSize + self.__MANAGEMENT_FRAME_SIZE;
			self.__UplinkmanagementFrame = self.__UplinkmanagementFrame + 1;
		else:
			print("Not Management Frame");

		if (ord(pac[0]) & ord(frameTypeMask1) == self.__CONTROL_FRAME_CODE):
			self.__UplinkcontrolFrame = self.__UplinkcontrolFrame + 1;
			print("Control packet");
			if (ord(pac[0]) == 132):
			#	print ("Control => Block Ack Request");
			#	print "Control Frame: Header size = ",self.__CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE;
			elif (ord(pac[0]) == 148):
			#	print ("Control => Block Ack");
			#	print "Control Frame: Header size = ",self.__CONTROL_BLOCK_ACK_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_BLOCK_ACK_FRAME_SIZE;
			#elif (ord(pac[0]) == 164):
			#	print ("Control => PS-Poll");
				# frame size unknown
			elif (ord(pac[0]) == 180):
			#	print ("Control => RTS");
			#	print "Control Frame: Header size = ",self.__CONTROL_RTS_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_RTS_FRAME_SIZE;
			#elif (ord(pac[0]) == 196):
			#	print ("Control => CTS");
			#	print "Control Frame: Header size = ",self.__CONTROL_CTS_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_CTS_FRAME_SIZE;
			elif (ord(pac[0]) == 212):
			#	print ("Control => ACK");
			#	print "Control Frame: Header size = ",self.__CONTROL_ACK_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_CTS_FRAME_SIZE;
			elif (ord(pac[0]) == 228):
			#	print ("Control => CF-end");
			#	print "Control Frame: Header size = ",self.__CONTROL_CF_END_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_CF_END_FRAME_SIZE;
			elif (ord(pac[0]) == 244):
			#	print ("Control => CF-end + CF-ack");
			#	print "Control Frame: Header size = ",self.__CONTROL_CF_END_ACK_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__CONTROL_CF_END_ACK_FRAME_SIZE;
		else:
			print("Not Control Packet");

		if (ord(pac[0]) & ord(frameTypeMask1) == self.__DATA_FRAME_CODE):
			print("Data packet");
			self.__UplinkdataFrame = self.__UplinkdataFrame + 1;
			if (ord(pac[0]) == 8):
		#		print ("Data => Data");
		#		print "Data Frame: Header size = ",self.__DATA_DATA_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__DATA_DATA_FRAME_SIZE;

			elif (ord(pac[0]) == 24):
		#		print ("Data => Data + CF-ack");
		#		print "Data Frame: Header size = ",self.__DATA_DATA_CF_ACK_FRAME_SIZE," byte";
				self.__uplinkFrameSize = self.__uplinkFrameSize + self.__DATA_DATA_CF_ACK_FRAME_SIZE;
		#	elif (ord(pac[0]) == 40):
		#		print ("Data => Data + CF-poll");
		#	elif (ord(pac[0]) == 56):
		#		print ("Data => Data +CF-ack +CF-poll");
		#	elif (ord(pac[0]) == 88):
		#		print ("Data => CF-ack");
		#	elif (ord(pac[0]) == 104):
		#		print ("Data => CF-poll");
		#	elif (ord(pac[0]) == 120):
		#		print ("Data => CF-ack +CF-poll");
		#	elif (ord(pac[0]) == 136):
		#		print ("Data => QoS data");
		#	elif (ord(pac[0]) == 152):
		#		print ("Data => QoS data + CF-ack");
		#	elif (ord(pac[0]) == 168):
		#		print ("Data => QoS data + CF-poll");
		#	elif (ord(pac[0]) == 184):
		#		print ("Data => QoS data + CF-ack + CF-poll");
		#	elif (ord(pac[0]) == 200):
		#		print ("Data => QoS Null");
		#	elif (ord(pac[0]) == 232):
		#		print ("Data => QoS + CF-poll (no data)");
		#	elif (ord(pac[0]) == 248):
		#		print ("Data => Qos + CF-ack (no data)");
		else: 
			print ("Not Data packet");


	def setDownlinkFrameSize(self,pac):
		frameTypeMask = binascii.unhexlify("FC");
		frameTypeMask1 = binascii.unhexlify("0C");
	
		#extract the type and the subtype
		frameBit = ord(pac[0]) & ord(frameTypeMask);
		
		if (ord(pac[0]) & ord(frameTypeMask1) == self.__MANAGEMENT_FRAME_CODE):
			print("Management packet");
			self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__MANAGEMENT_FRAME_SIZE;
			self.__DownlinkmanagementFrame = self.__DownlinkmanagementFrame + 1;
		else:
			print("Not Management Packet");	
		if (ord(pac[0]) & ord(frameTypeMask1) == self.__CONTROL_FRAME_CODE):
			print("Control packet");	
			self.__DownlinkcontrolFrame = self.__DownlinkcontrolFrame + 1;
			if (ord(pac[0]) == 132):
			#	print ("Control => Block Ack Request");
			#	print "Control Frame: Header size = ",self.__CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE;
			elif (ord(pac[0]) == 148):
			#	print ("Control => Block Ack");
			#	print "Control Frame: Header size = ",self.__CONTROL_BLOCK_ACK_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_BLOCK_ACK_FRAME_SIZE;
			#elif (ord(pac[0]) == 164):
			#	print ("Control => PS-Poll");
				# frame size unknown
			elif (ord(pac[0]) == 180):
			#	print ("Control => RTS");
			#	print "Control Frame: Header size = ",self.__CONTROL_RTS_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_RTS_FRAME_SIZE;
			#elif (ord(pac[0]) == 196):
			#	print ("Control => CTS");
			#	print "Control Frame: Header size = ",self.__CONTROL_CTS_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_CTS_FRAME_SIZE;
			elif (ord(pac[0]) == 212):
			#	print ("Control => ACK");
			#	print "Control Frame: Header size = ",self.__CONTROL_ACK_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_CTS_FRAME_SIZE;
			elif (ord(pac[0]) == 228):
			#	print ("Control => CF-end");
			#	print "Control Frame: Header size = ",self.__CONTROL_CF_END_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_CF_END_FRAME_SIZE;
			elif (ord(pac[0]) == 244):
			#	print ("Control => CF-end + CF-ack");
			#	print "Control Frame: Header size = ",self.__CONTROL_CF_END_ACK_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__CONTROL_CF_END_ACK_FRAME_SIZE;
		else:
			print("Not Control Packet");

		if (ord(pac[0]) & ord(frameTypeMask1) == self.__DATA_FRAME_CODE):
			print("Data packet");
			self.__DownlinkdataFrame = self.__DownlinkdataFrame + 1;
			if (ord(pac[0]) == 8):
		#		print ("Data => Data");
		#		print "Data Frame: Header size = ",self.__DATA_DATA_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__DATA_DATA_FRAME_SIZE;

			elif (ord(pac[0]) == 24):
		#		print ("Data => Data + CF-ack");
		#		print "Data Frame: Header size = ",self.__DATA_DATA_CF_ACK_FRAME_SIZE," byte";
				self.__donwlinkFrameSize = self.__donwlinkFrameSize + self.__DATA_DATA_CF_ACK_FRAME_SIZE;
		#	elif (ord(pac[0]) == 40):
		#		print ("Data => Data + CF-poll");
		#	elif (ord(pac[0]) == 56):
		#		print ("Data => Data +CF-ack +CF-poll");
		#	elif (ord(pac[0]) == 88):
		#		print ("Data => CF-ack");
		#	elif (ord(pac[0]) == 104):
		#		print ("Data => CF-poll");
		#	elif (ord(pac[0]) == 120):
		#		print ("Data => CF-ack +CF-poll");
		#	elif (ord(pac[0]) == 136):
		#		print ("Data => QoS data");
		#	elif (ord(pac[0]) == 152):
		#		print ("Data => QoS data + CF-ack");
		#	elif (ord(pac[0]) == 168):
		#		print ("Data => QoS data + CF-poll");
		#	elif (ord(pac[0]) == 184):
		#		print ("Data => QoS data + CF-ack + CF-poll");
		#	elif (ord(pac[0]) == 200):
		#		print ("Data => QoS Null");
		#	elif (ord(pac[0]) == 232):
		#		print ("Data => QoS + CF-poll (no data)");
		#	elif (ord(pac[0]) == 248):
		#		print ("Data => Qos + CF-ack (no data)");
		else: 
			print ("Not Data packet");

	def setDownlinkFrameSize1(self,pac):
		_MANAGEMENT_FRAME_SIZE = 24;
		_MANAGEMENT_FRAME_CODE = 0;


		_CONTROL_FRAME_CODE = 4;
		_CONTROL_BLOCK_ACK_FRAME_SIZE = 32; # with bitmap
		_CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE=32;
		_CONTROL_CTS_FRAME_SIZE=14;
		_CONTROL_ACK_FRAME_SIZE=14;
		_CONTROL_RTS_FRAME_SIZE=20;
		_CONTROL_CF_END_FRAME_SIZE=20; 		#accoding to PCF Algorithm
		_CONTROL_CF_END_ACK_FRAME_SIZE=20;


		_DATA_FRAME_CODE = 8;
		_DATA_DATA_FRAME_SIZE = 36;	#inspection from wireshark
		_DATA_DATA_CF_ACK_FRAME_SIZE = 36;	#cf-ack from PCF algorithm
		_DATA_QOS_DATA_FRAME_SIZE=38;


		#mask used to extract the Frame Type Mask
		frameTypeMask = binascii.unhexlify("FC");
		frameTypeMask1 = binascii.unhexlify("0C");
		#Extract Dot11 header and the other packet
		
			#extract the type and the subtype
		frameBit = ord(pac[0]) & ord(frameTypeMask);
			
		
		 
		if (ord(pac[0]) & ord(frameTypeMask1) == _MANAGEMENT_FRAME_CODE):
			print "Management Frame: Header size = ",_MANAGEMENT_FRAME_SIZE," byte";
			if (ord(pac[0]) == 0):
				print ("Management => Association Request");
			elif (ord(pac[0]) == 16):
				print ("Management => Association Response");
			elif (ord(pac[0]) == 32):
				print ("Management => ReAssociation Request");
			elif (ord(pac[0]) == 48):
				print ("Management => ReAssociation Response");
			elif (ord(pac[0]) == 64):
				print ("Management => Probe Request");
			elif (ord(pac[0]) == 80):
				print ("Management => Probe Response");
			elif (ord(pac[0]) == 128):
				print ("Management => Beacon");
			elif (ord(pac[0]) == 144):
				print ("Management => ATIM");
			elif (ord(pac[0]) == 160):
				print ("Management => Disassociation");
			elif (ord(pac[0]) == 176):
				print ("Management => Authentication");
			elif (ord(pac[0]) == 192):
				print ("Management => DeAuthentication");
		else:
			print ("Not management Packet");
			
		if (ord(pac[0]) & ord(frameTypeMask1) == _CONTROL_FRAME_CODE):

			if (ord(pac[0]) == 132):
				print ("Control => Block Ack Request");
				print "Control Frame: Header size = ",_CONTROL_BLOCK_ACK_REQUEST_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 148):
				print ("Control => Block Ack");
				print "Control Frame: Header size = ",_CONTROL_BLOCK_ACK_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 164):
				print ("Control => PS-Poll");
				# frame size unknown
			elif (ord(pac[0]) == 180):
				print ("Control => RTS");
				print "Control Frame: Header size = ",_CONTROL_RTS_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 196):
				print ("Control => CTS");
				print "Control Frame: Header size = ",_CONTROL_CTS_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 212):
				print ("Control => ACK");
				print "Control Frame: Header size = ",_CONTROL_ACK_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 228):
				print ("Control => CF-end");
				print "Control Frame: Header size = ",_CONTROL_CF_END_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 244):
				print ("Control => CF-end + CF-ack");
				print "Control Frame: Header size = ",_CONTROL_CF_END_ACK_FRAME_SIZE," byte";
			else:
				print("Not Control Packet");

		if (ord(pac[0]) & ord(frameTypeMask1) == _DATA_FRAME_CODE):
			if (ord(pac[0]) == 8):
				print ("Data => Data");
				print "Data Frame: Header size = ",_DATA_DATA_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 24):
				print ("Data => Data + CF-ack");	
				print "Data Frame: Header size = ",_DATA_DATA_CF_ACK_FRAME_SIZE," byte";
			elif (ord(pac[0]) == 40):
				print ("Data => Data + CF-poll");
			elif (ord(pac[0]) == 56):
				print ("Data => Data +CF-ack +CF-poll");
			elif (ord(pac[0]) == 88):
				print ("Data => CF-ack");
			elif (ord(pac[0]) == 104):
				print ("Data => CF-poll");
			elif (ord(pac[0]) == 120):
				print ("Data => CF-ack +CF-poll");
			elif (ord(pac[0]) == 136):
				print ("Data => QoS data");
			elif (ord(pac[0]) == 152):
				print ("Data => QoS data + CF-ack");
			elif (ord(pac[0]) == 168):
				print ("Data => QoS data + CF-poll");
			elif (ord(pac[0]) == 184):
				print ("Data => QoS data + CF-ack + CF-poll");
			elif (ord(pac[0]) == 200):
				print ("Data => QoS Null");
			elif (ord(pac[0]) == 232):
				print ("Data => QoS + CF-poll (no data)");
			elif (ord(pac[0]) == 248):
				print ("Data => Qos + CF-ack (no data)");
		else: 
			print ("Not Data packet");		

	
