#!/usr/bin/python3

import os
import sys
from pyof.v0x04.common.port import (
    ListOfPorts, Port, PortConfig, PortFeatures, PortNo, PortState
)
from pyof.v0x04.common.flow_match import Match, MatchType, OxmClass, OxmOfbMatchField, OxmTLV
from pyof.foundation.basic_types import DPID, HWAddress
from pyof.v0x04.common.flow_instructions import InstructionType
from pyof.v0x04.common.action import ActionType
from pyof.v0x04.asynchronous.packet_in import PacketInReason
import openflow_p4_mapping

#
# This is optional if you use proper PYTHONPATH
#
SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino', 'bfrt_grpc'))

PYTHON3_VER   = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                             'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

# Here is the most important module
import bfrt_grpc.client as gc
from tabulate import tabulate
import threading
import socket
import struct


ETH_P_ALL=0x0003  # /usr/include/linux/if_ether.h
OFPP_CONTROLLER=0xfffffffd

class BfRtController:
    def __init__(self, host="127.0.0.1", port=50052):
        self.host = host
        self.port = port
        self.interface = None
        self.bfrt_info = None

    def connect(self):
        #
        # Connect to the BF Runtime Server
        #
        for bfrt_client_id in range(10):
            try:
                self.interface = gc.ClientInterface(
                    grpc_addr = f"{self.host}:{self.port}",
                    client_id = bfrt_client_id,
                    device_id = 0,
                    num_tries = 5)
                print('Connected to BF Runtime Server as client', bfrt_client_id)
                break;
            except:
                print('Could not connect to BF Runtime server')
        else:
            raise Exception("Failed to connect to BF Runtime server")
        
        #
        # Get the information about the running program
        #
        self.bfrt_info = self.interface.bfrt_info_get()
        print('The target runs the program ', self.bfrt_info.p4_name_get())

        #
        # Establish that you are using this program on the given connection
        #
        if bfrt_client_id == 0:
            self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())

    def get_ports(self):
        """Get port status from Tofino."""
        # Barefoot speeds to OpenFlow tuple (current features, port bitrate in kbps)
        bf2of = {
            "BF_SPEED_1G": (PortFeatures.OFPPF_1GB_FD, 1000),
            "BF_SPEED_10G": (PortFeatures.OFPPF_10GB_FD, 10000),
            "BF_SPEED_25G": (PortFeatures.OFPPF_OTHER, 25000),
            "BF_SPEED_40G": (PortFeatures.OFPPF_40GB_FD, 40000),
            "BF_SPEED_40G_R2": (PortFeatures.OFPPF_40GB_FD, 40000),
            "BF_SPEED_50G": (PortFeatures.OFPPF_OTHER, 50000),
            "BF_SPEED_50G_CONS": (PortFeatures.OFPPF_OTHER, 50000),
            "BF_SPEED_100G": (PortFeatures.OFPPF_100GB_FD, 100000),
            "BF_SPEED_200G": (PortFeatures.OFPPF_OTHER, 200000),
            "BF_SPEED_400G": (PortFeatures.OFPPF_OTHER, 400000),
            "BF_SPEED_NONE": (0, 0),
        }
        port_local = Port(
            port_no=PortNo.OFPP_LOCAL,
            hw_addr=HWAddress('00:00:00:00:00:00'),
            name='local',
            config=PortConfig.OFPPC_PORT_DOWN,
            state=PortState.OFPPS_LINK_DOWN,
            curr=0,
            advertised=0,
            supported=0,
            peer=0,
            curr_speed=0,
            max_speed=0,
        )
        lop = ListOfPorts([port_local])
        dev_tgt = gc.Target(0)
        for (data, key) in self.bfrt_info.table_get("$PORT").entry_get(dev_tgt, []):
            port_data = data.to_dict()
            cur_feat, cur_speed = bf2of.get(port_data["$SPEED"], (0, 0))
            config = 0 if port_data["$PORT_ENABLE"] else PortConfig.OFPPC_PORT_DOWN
            state = PortState.OFPPS_LIVE if port_data["$PORT_UP"] else PortState.OFPPS_LINK_DOWN
            lop.append(Port(
                port_no=key.to_dict()["$DEV_PORT"]["value"],
                name=port_data["$PORT_NAME"],
                curr=cur_feat,
                config=config,
                state=state,
                advertised=0,
                supported=0,
                peer=0,
                curr_speed=cur_speed,
                max_speed=0,
            ))
        return lop

    def print_tables(self):
        # Print the list of tables in the "pipe" node
        dev_tgt = gc.Target(0)
        
        data = []
        for name in self.bfrt_info.table_dict.keys():
            if name.split('.')[0] == 'pipe':
                t = self.bfrt_info.table_get(name)
                table_name = t.info.name_get()
                if table_name != name:
                    continue
                table_type = t.info.type_get()
                try:
                    result = t.usage_get(dev_tgt)
                    table_usage = next(result)
                except:
                    table_usage = 'n/a'
                table_size = t.info.size_get()
                data.append([table_name, table_type, table_usage, table_size])
        print(tabulate(data, headers=['Full Table Name','Type','Usage','Capacity']))

    def get_tables(self):
        return [{}]

    def stream_wait_packets(self, ofswitch):
        def _stream_recv(stream_in_q):
            while True:
                try:
                    print("waiting for message")
                    msg = stream_in_q.get()
                    print(dir(msg))
                    print(msg.ListFields(), msg.SerializeToString(), "is port status?", msg.HasField("port_status_change_notification"))
                except:
                    pass

        self.stream_recv_thread = threading.Thread(
            target=_stream_recv, args=(self.interface.stream_in_q,))
        self.stream_recv_thread.daemon = True
        self.stream_recv_thread.start()

        #Enable port status change notification
        port_table = self.bfrt_info.table_get("$PORT")
        dev_tgt = gc.Target(0)
        port_table.attribute_port_status_change_set(dev_tgt, enable=True)

    def monitor_cpu_pcie_iface(self, interface, callback_pkt_in):
        def _read_packets(interface, callback_pkt_in):
            try:
                raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
                raw_socket.bind((interface, 0))
            except socket.error as e:
                print(f"Socket error: {e}")
                return
            while True:
                packet, addr = raw_socket.recvfrom(65535)
                # Process packet data here
                print(f"Packet received from: {addr}")
                # Unpack PacketIO header
                # bit<2>  reason
                # bit<14> in_port
                pktio_header = int.from_bytes(struct.unpack("!2s", packet[:2])[0], "big")
                reason = pktio_header >> 14
                in_port = pktio_header & 0b0011111111111111
                print(f"PacketIN: {in_port=} {reason=}")
                # Unpack Ethernet header
                ethernet_header = struct.unpack("!6s6sH", packet[2:16])
                print(f"Destination MAC: {ethernet_header[0].hex()}")
                print(f"Source MAC: {ethernet_header[1].hex()}")
                print(f"EtherType: {ethernet_header[2]:04x}")
                callback_pkt_in(reason, in_port, packet[2:])

        self.cpu_pcie_recv_thread = threading.Thread(
            target=_read_packets, args=(interface, callback_pkt_in,))
        self.cpu_pcie_recv_thread.daemon = True
        self.cpu_pcie_recv_thread.start()

    def send_packet_out_cpu_pcie(self, interface, out_port, data):
        try:
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            #raw_socket.bind((interface, 0))
        except socket.error as e:
            print(f"Socket error: {e}")
            return
        packet_out_hdr = struct.pack("!h", out_port)
        raw_socket.sendto(packet_out_hdr+data, (interface, 0))
        print("Packet sent")

    def create_oxm_vlan(self, vlan_keys):
        has_vlan = vlan_keys.get("has_vlan")
        vlan_vid = vlan_keys.get("vlan_vid")
        if not has_vlan or not vlan_vid or has_vlan["mask"] == 0:
            return
        vlan = None
        mask = None
        if has_vlan["value"] == 0:
            vlan = 0
        else:
        TODO

    def extract_match_priority_from_key(self, tbl_of, key):
        # key_dict={'$MATCH_PRIORITY': {'value': 50000}, 'eth_src': {'value': 0, 'mask': 0}, 'eth_type': {'value': 35020, 'mask': 65535}, 'has_vlan': {'value': 1, 'mask': 1}, 'in_port': {'value': 0, 'mask': 0}, 'ip_proto': {'value': 0, 'mask': 0}, 'vlan_vid': {'value': 3799, 'mask': 4095}} data_dict={'reason': 1, 'action_name': 'Ingress.vlan_control.send_packet_in', 'is_default_entry': False}
        # OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE {'value': 35020, 'mask': 65535}
        # OxmOfbMatchField.OFPXMT_OFB_VLAN_VID {'value': 3799, 'mask': 4095}
        #oxmtlv1 = OxmTLV(oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
        #                 oxm_field=OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE,
        #                 oxm_hasmask=False, oxm_value=b'\x88\xcc')
        #oxmtlv2 = OxmTLV(oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
        #                 oxm_field=OxmOfbMatchField.OFPXMT_OFB_VLAN_VID,
        #                 oxm_hasmask=False, oxm_value=b'\x1e\xd7')
        #match_1 = Match(match_type=MatchType.OFPMT_OXM,
        #             oxm_match_fields=[oxmtlv1, oxmtlv2])
        priority = None
        match = []
        vlan_keys = {}
        for field in list(key.field_dict.values()):
            data = key._get_val(field)
            if field.name in ["vlan_vid", "has_vlan"]:
                vlan_keys[field.name] = data
                if len(vlan_keys) == 2:
                    oxm = self.create_oxm_vlan(vlan_keys)
                    if oxm:
                        match.append(oxm)
                continue
            if field.name == "$MATCH_PRIORITY":
                priority = data["value"]
                continue
            if data["value"] == 0 and data["mask"] == 0:
                continue
            oxm_field = openflow_p4_mapping.match_fields[tbl_of].get(field.name)
            if not oxm_field:
                continue
            if field.name == "vlan_vid":
                pass
            else:
                fsize = openflow_p4_mapping.match_fields_bits_mask.get(oxm.oxm_field.value)
            print(str(oxm_field), data)
        return match, priority


    def get_entries(self):
        target = gc.Target(device_id=0, pipe_id=0xffff)
        for tbl_of, tbl_p4 in openflow_p4_mapping.tbl_of_p4.items():
            bfrt_table = self.bfrt_info.table_get(tbl_p4)
            resp = bfrt_table.entry_get(target)
            for data, key in resp:
                data_dict = data.to_dict()
                key_dict = key.to_dict()
                print(f"{key_dict=} {data_dict=}")
                match, priority = self.extract_match_priority_from_key(tbl_of, key)

    def get_table_from_flow_mod(self, flow_mod):
        table_id = flow_mod.table_id.value
        table_name = openflow_p4_mapping.tbl_of_p4.get(table_id)
        if not table_name:
            raise ValueError("Invalid table id")
        bfrt_table = self.bfrt_info.table_get(table_name)
        if not bfrt_table:
            raise ValueError("Invalid table not found on bfrt_info")
        return table_id, bfrt_table

    def make_keys(self, table_id, flow_mod):
        key_tuples = [gc.KeyTuple('$MATCH_PRIORITY', flow_mod.priority.value)]
        for oxm in flow_mod.match.oxm_match_fields:
            fname = openflow_p4_mapping.match_fields[table_id].get(oxm.oxm_field.value)
            if not fname:
                print("ERROR: invalid match field for table")
                continue
            value, mask = None, None
            if fname == "vlan_vid":
                value = int.from_bytes(oxm.oxm_value[:2], 'big')
                if value != 4096:
                    # ignore 4096
                    value &= 4095
                #value = value.to_bytes(2, byteorder='big')
                if oxm.oxm_hasmask:
                    mask = int.from_bytes(oxm.oxm_value[2:], 'big')
                    if mask != 4096:
                        # ignore 4096
                        mask &= 4095
                    #mask = mask.to_bytes(2, byteorder='big')
                else:
                    mask = 0xFFF
                if value == 4096 and mask == 4096:
                    # Only packets with a VLAN tag regardless of its value
                    fname, value, mask = "has_vlan", 1, 1
                elif value == 0 and not oxm.oxm_hasmask:
                    # Only packets without a VLAN tag
                    fname, value, mask = "has_vlan", 0, 1
                else:
                    # otherwise: Only packets with VLAN tag
                    key_tuples.append(gc.KeyTuple("has_vlan", 1, 1))

            else:
                fsize = openflow_p4_mapping.match_fields_bits_mask.get(oxm.oxm_field.value)
                if fsize:
                    value = oxm.oxm_value[:fsize]
                else:
                    value = oxm.oxm_value
                if oxm.oxm_hasmask:
                    if not fsize:
                        raise ValueError("Match Field with mask but no size defined!")
                    mask = oxm.oxm_value[fsize:]
                else:
                    mask = b'\xff'*len(value)
                value = bytearray(value)
                mask = bytearray(mask)

            print(str(oxm.oxm_field), fname, value, mask)
            key_tuples.append(gc.KeyTuple(fname, value, mask))

            #result[oxm.oxm_field] = oxm.oxm_value
            #if oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_VLAN_VID:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_ETH_SRC:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_ETH_DST:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_IPV4_SRC:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_IPV4_DST:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_IP_PROTO:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_IN_PORT:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_TCP_SRC:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_TCP_DST:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_UDP_SRC:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_UDP_DST:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_ICMPV4_TYPE:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_IPV6_SRC:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_IPV6_DST:
            #    # TODO
            #    pass
            #elif oxm.oxm_field == OxmOfbMatchField.OFPXMT_OFB_ICMPV6_TYPE:
            #    # TODO
            #    pass
        return key_tuples

    def add_entry(self, flow_mod):
        # ADD FlowMod: {'flags': UBInt16(FlowModFlags(1)), 'out_port': 4294967295, 'command': UBInt8(<FlowModCommand.OFPFC_ADD: 0>), 'cookie': '0xab00bbccddeeff01', 'cookie_mask': '0x0', 'table_id': 0, 'idle_timeout': UBInt16(0), 'hard_timeout': UBInt16(0), 'buffer_id': UBInt32(4294967295), 'out_group': UBInt32(4294967295), 'match': {'OxmOfbMatchField.OFPXMT_OFB_VLAN_VID': "b'\\x1e\\xd7'", 'OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE': "b'\\x88\\xcc'"}, 'instructions': [{'type': 'OFPIT_APPLY_ACTIONS', 'actions': [{'type': UBInt16(<ActionType.OFPAT_OUTPUT: 0>), 'port': UBInt32(4294967293), 'max_length': UBInt16(65535)}]}]}
        print("ADD FlowMod:")
        table_id, bfrt_table = self.get_table_from_flow_mod(flow_mod)

        key_tuples = self.make_keys(table_id, flow_mod)

        key = bfrt_table.make_key(key_tuples)

        # [{'type': 'OFPIT_APPLY_ACTIONS', 'actions': [{'type': UBInt16(<ActionType.OFPAT_OUTPUT: 0>), 'port': UBInt32(4294967293), 'max_length': UBInt16(65535)}]}]
        action_name = []
        action_data = []
        for instruction in flow_mod.instructions:
            if instruction.instruction_type == InstructionType.OFPIT_APPLY_ACTIONS:
                for action in instruction.actions:
                    if action.action_type == ActionType.OFPAT_OUTPUT:
                        if action.port.value == OFPP_CONTROLLER:
                            action_name.append("send_packet_in")
                            action_data.append(["reason", PacketInReason.OFPR_ACTION.value])
                        else:
                            action_name.append("output")
                            action_data.append(["port", action.port.value])
            elif instruction.instruction_type == InstructionType.OFPIT_GOTO_TABLE:
                print("goto_table")
            else:
                raise ValueError(f"Unsupported instruction type {instruction.instruction_type}")

        print("ACTIONS:", action_name, action_data)

        data_tuples = [gc.DataTuple(k, v) for k,v in action_data]
        data_name = "drop"
        if action_name:
            data_name = "_".join(action_name)

        data = bfrt_table.make_data(data_tuples, data_name)

        target = gc.Target(device_id=0, pipe_id=0xffff)

        resp = bfrt_table.entry_add(target, [key], [data])

        print(resp)

    def del_entry(self, flow_mod):
        print("DEL FlowMod:")

    def del_entry_strict(self, flow_mod):
        print("DEL FlowMod strict:")
        # Received FlowMod: {'flags': UBInt16(FlowModFlags(1)), 'out_port': 4294967295, 'command': UBInt8(<FlowModCommand.OFPFC_DELETE_STRICT: 4>), 'cookie': '0x0', 'cookie_mask': '0x0', 'priority': 1000, 'table_id': 0, 'idle_timeout': UBInt16(0), 'hard_timeout': UBInt16(0), 'buffer_id': UBInt32(4294967295), 'out_group': UBInt32(4294967295), 'match': {<OxmOfbMatchField.OFPXMT_OFB_VLAN_VID: 6>: b'\x1e\xd7', <OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE: 5>: b'\x88\xcc'}, 'instructions': [{'type': 'OFPIT_APPLY_ACTIONS', 'actions': [{'type': UBInt16(<ActionType.OFPAT_OUTPUT: 0>), 'port': UBInt32(4294967293), 'max_length': UBInt16(65535)}]}]}
        table_id, bfrt_table = self.get_table_from_flow_mod(flow_mod)

        key_tuples = self.make_keys(table_id, flow_mod)

        key = bfrt_table.make_key(key_tuples)

        target = gc.Target(device_id=0, pipe_id=0xffff)

        client_metadata = [("error_in_resp", "1")]

        resp = bfrt_table.entry_del(target, [key], metadata=client_metadata)

        print(resp)
