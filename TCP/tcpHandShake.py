#!/usr/bin/python
from scapy.all import *
import time
import multiprocessing



def handShake():
	sequence=1500;

	#sends sync patcket to the server
	ip=IP(src="172.16.133.156", dst="172.16.0.254")
	TCP_SYN=TCP(sport=1500, dport=1500, flags="S", seq=sequence)
	#start the timer
	start_time = time.time();

	TCP_SYNACK=sr1(ip/TCP_SYN)


	#recieves the packet as TCP_SYNACK;
#	TCP_SYNACK.display();
	#check if the packet have ack and syn both or not

	my_ack = TCP_SYNACK.seq + 1
	TCP_ACK=TCP(sport=1500, dport=1500, flags="A", seq=sequence+1, ack=my_ack)
	send(ip/TCP_ACK)
	#end the timer
	finish_time = time.time();

	
	print "The time taken for TCP handshake is: ",  finish_time - start_time,"s";

	

if __name__ == "__main__":
	
	#multiprocessing is used to stop the program if the tcp handshake is not successful
	p = multiprocessing.Process(target=handShake, name="handShake");
    	p.start()

	p.join(10)

	# If thread is active
	if p.is_alive():
	    	print "too long to run... let's kill it..."

		    # Terminate foo
	    	p.terminate()
	    	p.join()
		print "Abnormal time taken";
	

    	
