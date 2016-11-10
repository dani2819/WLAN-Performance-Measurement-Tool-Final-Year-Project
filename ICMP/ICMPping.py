#!/usr/bin/env
import subprocess


# function used to find the SSID IP of the Access Point
def findDefaultIP(output):
	out=[];
	defInd = output.find("default");
	offset = 12;
	i=0;
	while(output[defInd+offset+i] != " "):
		
		i=i+1;
	return output[defInd+offset:defInd+offset+i];


# function used to find the Success Rate of the Ping
def findSuccessRate(output):
	out=[];
	percent = output.find("%");
	i=1;
	while(output[percent-i] != " "):
		i = i+1;
	
	if i-1 == 1:
		return output[percent-1];
	else:
		return output[percent-i+1:percent];


# function used to find the Average Round trip Ping time
def findRRTAverage (output):
	backslash = 0;
	rrt=[];
	for i in range(1,len(output)):
		if output[len(output)-i] == "/":
			backslash = backslash+1;	
		if backslash == 2:
			rrt.append(output[len(output)-i]);
		if backslash == 3:
			rrt = rrt[::-1];
			return ''.join(rrt[0:len(rrt)-1]);
		

## call date command ##
p = subprocess.Popen("ip route", stdout=subprocess.PIPE, shell=True);

(output, err) = p.communicate()
 
## Wait for date to terminate. Get return returncode ##
p_status = p.wait()

if(output != ''):
	defIP = findDefaultIP(output);
	print(defIP);
	## call date command ##
	p = subprocess.Popen("ping -c 10 " + defIP, stdout=subprocess.PIPE, shell=True);

	(output, err) = p.communicate()
	 
	## Wait for date to terminate. Get return returncode ##
	p_status = p.wait()
	print "Complete Command: ",output
	print output.find("%");
	out = findRRTAverage(output);
	if out:
		rtt = float(out); #Corrected
		print "Command output roundtrip : ", str(rtt) # give correct answer to 1 decimal place

		#Determine the success rate of the packet ping
		packetLoss = float(findSuccessRate(output));
		print "Success Rate: " + str(100 - packetLoss)
	else:
		print("Destination Unreachable Incorrect IP");
else:
	print("Not connected");
