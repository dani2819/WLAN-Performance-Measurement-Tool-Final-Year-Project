#!/usr/bin/env
import subprocess

class MyICMP:

	def __init__(self,BaseIP = '192.168.1.1',noPing=10):
		#Base IP of the Base station
		self.__BaseIP = BaseIP;
		#Success Rate of the ICMP Ping
		self.__successRate=0;
		#Round Trip Time of the ICMP Ping
		self.__roundTripTime=0;
		self.__output='';
		self.__noPing=noPing;
		self.__error=0;
		return;

	#setters and getters
	def getBaseIP(self):return self.__BaseIP;
	def setBaseIP(self,BaseIP): self.__BaseIP = BaseIP;

	def getSuccessRate(self): return self.__successRate;
	
	def getroundTripTime(self): return self.__roundTripTime;

	def getNoPing(self): return self.__noPing;
	def setNoPing(self,noPing): self.__noPing = noPing;

	def getError(self): return self.__error;


	# function used to find the SSID IP of the Access Point
	def findDefaultIP(self,output):
		out=[];
		defInd = output.find("default");
		offset = 12;
		i=0;
		while(output[defInd+offset+i] != " "):
			
			i=i+1;
		return output[defInd+offset:defInd+offset+i];

	def generateOutput(self):
		## find default ip of the base station ##
		p = subprocess.Popen("ip route", stdout=subprocess.PIPE, shell=True);
		(output, err) = p.communicate()
		## Wait for the shell command to terminate ##

		if(output != ''):
			p_status = p.wait()
			defIP = self.findDefaultIP(output);
			self.setBaseIP(defIP);
			
			## Shell command for the ping call ##

			
			p = subprocess.Popen("ping -c " + str(self.__noPing) +" " + defIP, stdout=subprocess.PIPE, shell=True);

			(output, err) = p.communicate()
			print ("This is ping output");
			print (output);	 
			## Wait for date to terminate. Get return returncode ##
			p_status = p.wait()
			#assign the local variable output to the variable of the class
			self.__output = output;
		else:
			self.__error = 1;

		return;

	# Methods used to find the Round Trip time and the Success rate
	# to work correctly first the RRT Average method must be called and if the answer is correct than
	# SuccessRate method is called.
	def findRRTAverage (self):
		backslash = 0;
		rrt=[];
		for i in range(1,len(self.__output)):
			if self.__output[len(self.__output)-i] == "/":
				backslash = backslash+1;	
			if backslash == 2:
				rrt.append(self.__output[len(self.__output)-i]);
			if backslash == 3:
				rrt = rrt[::-1];
				return ''.join(rrt[0:len(rrt)-1]);


	def findSuccessRate(self):
		out=[];
		percent = self.__output.find("%");
		i=1;
		while(self.__output[percent-i] != " "):
			i = i+1;
		
		if i-1 == 1:
			return self.__output[percent-1];
		else:
			return self.__output[percent-i+1:percent];


	def callPing(self):
		self.generateOutput();
		if(self.__error != 1):
		
			out = self.findRRTAverage();
			if out:
				
				self.__roundTripTime = float(out); #Corrected
				
				#Determine the success rate of the packet ping
				packetLoss = float(self.findSuccessRate());
				self.__successRate = 100 - packetLoss;
			else:
				self.__error = 1
		else:
			self.__error = 1;		
		return

