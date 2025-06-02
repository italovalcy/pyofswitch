import asyncio
import time
import traceback

from pyof.utils import unpack
from pyof.v0x04.symmetric.hello import Hello
from pyof.foundation.basic_types import DPID, HWAddress
from pyof.v0x04.controller2switch.features_reply import FeaturesReply
from pyof.v0x04.symmetric.echo_reply import EchoReply
from pyof.v0x04.controller2switch.common import MultipartType
from pyof.v0x04.controller2switch.multipart_reply import Desc, MultipartReply, MultipartReplyFlags
from pyof.v0x04.asynchronous.packet_in import PacketIn, PacketInReason
from pyof.v0x04.common.port import (
    ListOfPorts, Port, PortConfig, PortFeatures, PortNo, PortState
)
from pyof.v0x04.controller2switch.multipart_reply import PortStats, FlowStats, TableStats
from pyof.v0x04.common.action import ActionOutput, ListOfActions
from pyof.v0x04.common.flow_instructions import (
    InstructionApplyAction, ListOfInstruction)
from pyof.v0x04.common.flow_match import (
    Match, MatchType, OxmClass, OxmOfbMatchField, OxmTLV)
from pyof.v0x04.controller2switch.barrier_reply import BarrierReply
from pyof.v0x04.controller2switch.features_reply import Capabilities
from pyof.v0x04.common.constants import OFP_NO_BUFFER
from pyof.v0x04.controller2switch.flow_mod import FlowModCommand

import config
from utils import of_dict, of_slicer

class PyOFSwitch:
    def __init__(self, host, port, controller=None):
        self.host = host
        self.port = port
        self.controller = controller
        self.reader = None
        self.writer = None
        self.is_connected = False
        self.is_new_connection = None
        self.loop = asyncio.get_running_loop()
        self.last_seen = 0

    async def sender(self):
        i = 0
        while self.is_connected:
            #msg = f"test 123 - {i}"
            #i+=1
            #print("Sending " + msg)
            #self.writer.write(msg.encode())
            #await self.writer.drain()
            await asyncio.sleep(5)

    async def send_hello(self):
        """Send a Hello to new connection."""
        print("Sending hello")
        hello = Hello()
        return await self.send_of_msg(hello)

    async def send_of_msg(self, msg):
        try:
            packet = msg.pack()
            self.writer.write(packet)
            await self.writer.drain()
        except Exception as err:
            print(f'Invalid OF message: {err}')
            return False
        return True
    
    async def open_connection(self,):
        print("Opening OF Controller...")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.is_connected = True
        self.is_new_connection = True
        remaining_data = b''
        await self.send_hello()
        self.loop.create_task(self.sender())
        while self.is_connected:
            if self.reader.at_eof():
                break
            new_data = await self.reader.read(65536)
            print(f"Received OF msg len={len(new_data)}")
            data = remaining_data + new_data
            packets, remaining_data = of_slicer(data)
            for packet in packets:
                if not self.is_connected:
                    break
                try:
                    message = unpack(packet)
                except Exception as exc:
                    print(f"Error while unpacking: {exc}")
                ofp_msg_type = message.header.message_type.name.lower()
                print(f"Connection IN OFP, ver: {message.header.version}, type: {ofp_msg_type}, xid: {message.header.xid}")
                handle_func = getattr(self, f"handle_{ofp_msg_type}", self.handle_default)
                await handle_func(message)
        print("connection closed")
        self.is_connected = False
        # TODO: finish writer

    async def handle_ofpt_hello(self, msg):
        self.last_seen = time.time()

    async def handle_ofpt_set_config(self, msg):
        print(f"Executing set config {msg.flags=} {msg.miss_send_len=}")

    async def handle_ofpt_echo_request(self, msg):
        reply = EchoReply(msg.header.xid)
        return await self.send_of_msg(reply)

    async def handle_ofpt_features_request(self, msg):
        tables = self.controller.get_tables()
        feat_reply = FeaturesReply(
            xid=msg.header.xid,
            datapath_id=DPID(config.MYDPID),
            n_buffers=3145728, ## TODO: check where this number come from on the Noviflows
            n_tables=len(tables),
            auxiliary_id=0,
            capabilities=Capabilities.OFPC_FLOW_STATS | Capabilities.OFPC_TABLE_STATS | Capabilities.OFPC_PORT_STATS | Capabilities.OFPC_GROUP_STATS | Capabilities.OFPC_QUEUE_STATS, 
            reserved=0x00000000,
        )
        return await self.send_of_msg(feat_reply)

    async def handle_ofpt_multipart_request(self, msg):
        """Handle OF 1.3 multipart request msg."""
        if msg.multipart_type == MultipartType.OFPMP_FLOW:
            await self.handle_multipart_flow_stats(msg)
        elif msg.multipart_type == MultipartType.OFPMP_TABLE:
            await self.handle_multipart_table_stats(msg)
        elif msg.multipart_type == MultipartType.OFPMP_PORT_STATS:
            await self.handle_multipart_port_stats(msg)
        elif msg.multipart_type == MultipartType.OFPMP_PORT_DESC:
            await self.handle_port_desc(msg)
        elif msg.multipart_type == MultipartType.OFPMP_DESC:
            await self.handle_switch_desc(msg)

    async def handle_multipart_flow_stats(self, msg):
        """Handle OF multipart FlowStats."""
        print("-------------------")
        self.controller.get_entries()
        print("-------------------")

        print(f"handle OF multipart FlowStats: {msg.body=}")
        # match
        oxmtlv1 = OxmTLV(oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
                         oxm_field=OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE,
                         oxm_hasmask=False, oxm_value=b'\x88\xcc')
        oxmtlv2 = OxmTLV(oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
                         oxm_field=OxmOfbMatchField.OFPXMT_OFB_VLAN_VID,
                         oxm_hasmask=False, oxm_value=b'\x1e\xd7')
        match_1 = Match(match_type=MatchType.OFPMT_OXM,
                     oxm_match_fields=[oxmtlv1, oxmtlv2])
        # instructions
        action_output = ActionOutput(port=PortNo.OFPP_CONTROLLER)
        loa = ListOfActions([action_output])
        instruction = InstructionApplyAction(loa)
        instructions_1 = ListOfInstruction([instruction])
        # Flow Stats
        flow_stats_1 = FlowStats(table_id=0, duration_sec=56,
                         duration_nsec=635000000, priority=1000, idle_timeout=0,
                         hard_timeout=0, flags=0x00000001,
                         cookie=0x0000000000000000, packet_count=18,
                         byte_count=756, match=match_1,
                         instructions=instructions_1)
        flow_stats_1.length = flow_stats_1.get_size()
        # match_2
        oxmtlv3 = OxmTLV(oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
                         oxm_field=OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE,
                         oxm_hasmask=False, oxm_value=b'\x88\xcd')
        oxmtlv4 = OxmTLV(oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
                         oxm_field=OxmOfbMatchField.OFPXMT_OFB_VLAN_VID,
                         oxm_hasmask=False, oxm_value=b'\x1e\xd8')
        match_2 = Match(match_type=MatchType.OFPMT_OXM,
                     oxm_match_fields=[oxmtlv3, oxmtlv4])
        # instructions_2
        action_output_2 = ActionOutput(port=2)
        loa_2 = ListOfActions([action_output_2])
        instruction_2 = InstructionApplyAction(loa_2)
        instructions_2 = ListOfInstruction([instruction_2])
        # Flow Stats
        flow_stats_2 = FlowStats(table_id=0, duration_sec=56,
                         duration_nsec=635000000, priority=1000, idle_timeout=0,
                         hard_timeout=0, flags=0x00000001,
                         cookie=0x0000000000000000, packet_count=18,
                         byte_count=756, match=match_2,
                         instructions=instructions_2)
        flow_stats_2.length = flow_stats_2.get_size()
        reply = MultipartReply(
            xid=msg.header.xid,
            multipart_type=MultipartType.OFPMP_FLOW,
            flags=0,
            body=[flow_stats_1, flow_stats_2],
        )
        await self.send_of_msg(reply)

    async def handle_multipart_table_stats(self, msg):
        """Handle OF multipart TableStats."""
        print(f"handle OF multipart TableStats: {msg.body=}")
        table_stats_1 = TableStats(
            table_id = 0,
            active_count = 10,
            lookup_count = 20,
            matched_count = 30,
        )
        table_stats_2 = TableStats(
            table_id = 1,
            active_count = 10,
            lookup_count = 20,
            matched_count = 30,
        )
        reply = MultipartReply(
            xid=msg.header.xid,
            multipart_type=MultipartType.OFPMP_TABLE,
            flags=0,
            body=[table_stats_1, table_stats_2],
        )
        await self.send_of_msg(reply)

    async def handle_multipart_port_stats(self, msg):
        """Handle OF multipart PortStats."""
        print(f"handle OF multipart PortStats: {msg.body=}")
        ps1 = PortStats(
            port_no=PortNo.OFPP_LOCAL,
            rx_packets=0,
            tx_packets=0,
            rx_bytes=0,
            tx_bytes=0,
            rx_dropped=0,
            tx_dropped=0,
            rx_errors=0,
            tx_errors=0,
            rx_frame_err=0,
            rx_over_err=0,
            rx_crc_err=0,
            collisions=0,
            duration_sec=0,
            duration_nsec=0,
        )
        ps2 = PortStats(
            port_no=1,
            rx_packets=0,
            tx_packets=0,
            rx_bytes=0,
            tx_bytes=0,
            rx_dropped=0,
            tx_dropped=0,
            rx_errors=0,
            tx_errors=0,
            rx_frame_err=0,
            rx_over_err=0,
            rx_crc_err=0,
            collisions=0,
            duration_sec=0,
            duration_nsec=0,
        )
        ps3 = PortStats(
            port_no=2,
            rx_packets=0,
            tx_packets=0,
            rx_bytes=0,
            tx_bytes=0,
            rx_dropped=0,
            tx_dropped=0,
            rx_errors=0,
            tx_errors=0,
            rx_frame_err=0,
            rx_over_err=0,
            rx_crc_err=0,
            collisions=0,
            duration_sec=0,
            duration_nsec=0,
        )
        reply = MultipartReply(
            xid=msg.header.xid,
            multipart_type=MultipartType.OFPMP_PORT_STATS,
            flags=0,
            body=[ps1, ps2, ps3],
        )
        await self.send_of_msg(reply)

    async def handle_port_desc(self, msg):
        """Handle OF multipart PortDesc."""
        print("handle OF multipart PortDesc")
        ports = self.controller.get_ports()
        #port2 = Port(port_no=1,
        #             hw_addr=HWAddress('4e:bf:ca:27:8e:ca'),
        #             name='s1-eth1',
        #             config=0,
        #             state=PortState.OFPPS_LIVE,
        #             curr=PortFeatures.OFPPF_10GB_FD | PortFeatures.OFPPF_COPPER,
        #             advertised=0,
        #             supported=0,
        #             peer=0,
        #             curr_speed=10000000,
        #             max_speed=0)
        #port3 = Port(port_no=2,
        #             hw_addr=HWAddress('26:1f:b9:5e:3c:c7'),
        #             name='s1-eth2',
        #             config=0,
        #             state=PortState.OFPPS_LIVE,
        #             curr=PortFeatures.OFPPF_10GB_FD | PortFeatures.OFPPF_COPPER,
        #             advertised=0,
        #             supported=0,
        #             peer=0,
        #             curr_speed=10000000,
        #             max_speed=0)
        #lop = ListOfPorts([port1, port2, port3])
        reply = MultipartReply(
            xid=msg.header.xid,
            multipart_type=MultipartType.OFPMP_PORT_DESC,
            flags=0,
            body=ports,
        )
        await self.send_of_msg(reply)

    async def handle_switch_desc(self, msg):
        """Handle OF multipart SwitchDesc."""
        print("handle OF multipart SwitchDesc")
        self.controller.print_tables()
        switch_desc = Desc(
            mfr_desc="MANUFACTURER DESCRIPTION",
            hw_desc="HARDWARE DESCRIPTION",
            sw_desc="SOFTWARE DESCRIPTION",
            serial_num="SERIAL NUMBER",
            dp_desc="DATAPATH DESCRIPTION",
        )
        reply = MultipartReply(
            xid=msg.header.xid,
            multipart_type=MultipartType.OFPMP_DESC,
            flags=MultipartReplyFlags.OFPMPF_REPLY_MORE,
            body=switch_desc,
        )
        await self.send_of_msg(reply)

    async def handle_ofpt_flow_mod(self, flow_mod):
        flowmod_dict = of_dict(flow_mod)
        print(f"Received FlowMod: {flowmod_dict}")
        flow_cmd_map = {
            FlowModCommand.OFPFC_ADD.value: self.controller.add_entry,
            FlowModCommand.OFPFC_DELETE.value: self.controller.del_entry,
            FlowModCommand.OFPFC_DELETE_STRICT.value: self.controller.del_entry_strict,
        }
        try:
            flow_cmd_map[flow_mod.command.value](flow_mod)
        except KeyError:
            print("==> Unknown FlowMod")
        except Exception as exc:
            err = traceback.format_exc().replace("\n", ", ")
            print(f"==> Error FlowMod: {exc} -- {err}")

    async def handle_flowmod_delete_strict(self, flowmod_dict):
        print(f"DELETE_STRICT FlowMod: {flowmod_dict}")

    async def handle_flowmod_delete(self, flowmod_dict):
        print(f"DELETE FlowMod: {flowmod_dict}")


    async def handle_ofpt_barrier_request(self, msg):
        reply = BarrierReply(
            xid=msg.header.xid,
        )
        await self.send_of_msg(reply)

    async def handle_default(self, message):
        ofp_msg_type = message.header.message_type.name.lower()
        print(f"Default handler for {ofp_msg_type}")

    def callback_send_packet_in(self, reason, in_port, packet):
        oxmtlv = OxmTLV(
            oxm_class=OxmClass.OFPXMC_OPENFLOW_BASIC,
            oxm_field=OxmOfbMatchField.OFPXMT_OFB_IN_PORT,
            oxm_hasmask=False, oxm_value=in_port.to_bytes(4, "big"),
        )
        match = Match(
            match_type=MatchType.OFPMT_OXM,
            oxm_match_fields=[oxmtlv]
        )
        try:
            ofp_reason = PacketInReason(reason)
        except ValueError:
            ofp_reason = PacketInReason.OFPR_ACTION
        msg = PacketIn(
            xid=0, ## TODO
            buffer_id=OFP_NO_BUFFER,
            total_len=90, ## TODO
            reason=ofp_reason,
            table_id=0,  ## TODO
            cookie=0x0000000000000000,  # TODO
            match=match,
            data=packet,
        )
        asyncio.run(self.send_of_msg(msg))
