#!/usr/bin/python
from scapy.all import *import time
import multiprocessing
from ICMP import *

class myTCP:
	def __init__(self,destIP='192.168.1.1'):
		self.__TCPHandshakeTime=0.0;
		self.__TCPUplinkThroughput=0.0;
		self.__TCPDownlinkThroughput=0.0;
		self.__TCPRetranmissionRate=0.0;
		self.__BaseIP = destIP;
		self.__error=0;
	def getTCPHandshakeTime(self): return self.__TCPHandshakeTime;
	def getTCPUplinkThroughput(self): return self.__TCPUplinkThroughput;
	def getTCPDownlinkThroughput(self): return self.__TCPDownlinkThroughput;


	def getBaseIP(self):
		icmp = MyICMP();
		icmp.generateOutput();
		if icmp.getError():
			self.__error = 1;
			return;
		else:
			self.__BaseIP = icmp.getBaseIP();
			print (self.__BaseIP);
