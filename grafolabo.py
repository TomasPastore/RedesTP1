from scapy.all import *
from collections import defaultdict
from ipaddress import ip_address

filename = "Sniff Alsea (WiFi)/Alsea_wifi_60K.pcap"

packets = rdpcap(filename)

nodos_broadcast = defaultdict(set)
clusters = defaultdict(set)

def get_cluster(ip):
	ip = ip_address(unicode(ip))
	cluster = str(ip_address(int(ip) & 0b1111111111111111111111100000000))
	return cluster

def get_last(ip):
	ip = ip_address(unicode(ip))
	cluster = str(int(ip_address(int(ip) & 0b11111111)))
	return cluster

grafo = defaultdict(set)

for p in packets:
	if p.haslayer(ARP):
		if p.payload.psrc != '0.0.0.0' and p.payload.pdst != '0.0.0.0':
			nodos_broadcast[p.payload.psrc].add(p.payload.pdst)
		
		# grafo[p.payload.psrc].add(p.payload.pdst)
		# grafo[p.payload.pdst].add(p.payload.psrc)

		# clusters[get_cluster(p.payload.psrc)].add(p.payload.psrc)
		# clusters[get_cluster(p.payload.pdst)].add(p.payload.pdst)

print 'strict graph G{'
# for mask,cip in clusters.items():

# 	print u'\tsubgraph cluster_'+str(counter)+u' {'
# 	#print u'\tnode [style=filled,color=grey];'
# 	print u'\tcolor=blue;'
# 	print u'\tlabel = "'+ str(mask) +'";'

# 	for ip in cip:
# 		print '\t\t"'+ ip + '" [label='+get_last(ip)+'];'

# 	print '\t}'
# 	counter += 1 

for k,v in nodos_broadcast.items():
	for n in v:
		if n != k:
			print '\t"'+k+'"' + ' -- ' + '"'+n+'"' + ';'

print '}'