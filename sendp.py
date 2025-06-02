from scapy.all import *
class PacketOut(Packet):
    name = "PacketOut "
    fields_desc=[
        BitField("egress_port", 0, 16),
    ]

sendp(PacketOut(egress_port=64)/Ether(src="00:90:fb:76:ce:bc", dst="01:02:03:04:05:06")/IP(dst="1.2.3.4",ttl=4), iface="ens1")
