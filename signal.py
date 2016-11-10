#!/usr/bin/env
from scapy.all import *
import scapy_ex
from math import pow

p = rdpcap("Wire1.pcap");

p[2].show();
signalStrength = float(p[2][RadioTap].dBm_AntSignal);

print(float(p[2][RadioTap].dBm_AntSignal));
signalStrength_mW=0.0;
if signalStrength > 0:
	signalStrength_mW = pow(10,signalStrength/10);
else:
	signalStrength_mW = 1/(pow(10,abs(signalStrength)/10));
print(signalStrength_mW);