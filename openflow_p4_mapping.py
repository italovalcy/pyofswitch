from pyof.v0x04.common.flow_match import OxmOfbMatchField

tbl_of_p4 = {
    0: "pipe.Ingress.vlan_control.tbl_0",
}
tbl_p4_of = {}

match_fields = {
    0: {
        "vlan_vid": OxmOfbMatchField.OFPXMT_OFB_VLAN_VID,
        "eth_type": OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE,
        "in_port":  OxmOfbMatchField.OFPXMT_OFB_IN_PORT,
        "eth_src":  OxmOfbMatchField.OFPXMT_OFB_ETH_SRC,
        "ip_proto": OxmOfbMatchField.OFPXMT_OFB_IP_PROTO,
#      TODO: ipv6 for OFPXMT_OFB_IP_PROTO
#      TODO: implement on p4 OFPXMT_OFB_IPV4_DST
#      TODO: implement on p4 OFPXMT_OFB_TCP_DST
#      TODO: implement on p4 OFPXMT_OFB_UDP_DST
    },
}

# details the size (bytes) of the match field which is necessary in case it has mask
# if it does not have mask, then oxm_value will be self contained
match_fields_bits_mask = {
    OxmOfbMatchField.OFPXMT_OFB_IN_PORT.value: None,
    OxmOfbMatchField.OFPXMT_OFB_VLAN_VID.value: 2,
    OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE.value: None,
    OxmOfbMatchField.OFPXMT_OFB_IP_PROTO.value: None,
}

for k,v in tbl_of_p4.items():
    tbl_p4_of[v] = k

for table in match_fields:
    for k, v in match_fields[table].copy().items():
        match_fields[table][v.value] = k
