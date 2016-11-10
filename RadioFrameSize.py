#!/usr/bin/env
from subprocess import call
from scapy.all import *
import binascii
import struct
import datetime
import csv
import subprocess

packets = rdpcap('uplink.pcap')

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
for i in range(0,len(packets)):
	#Extract Dot11 header and the other packet
	pac = str(packets[i][Dot11])
	#extract the type and the subtype
	frameBit = ord(pac[0]) & ord(frameTypeMask);
	
	print "Packet no: ",i;
 
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
