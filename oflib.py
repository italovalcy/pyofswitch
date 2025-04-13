"""OpenFlow 1.3 lib to convert to dict."""
import traceback
from struct import unpack
from pyof.foundation.basic_types import BinaryData
from pyof.foundation.basic_types import FixedTypeList
from pyof.v0x04.common.flow_instructions import InstructionType


class OpenFlowDict:
    def __init__(self, msg):
        self.msg = msg
        self.msg_type = msg.header.message_type.name.lower()
        self.msg_xid = msg.header.xid

    def as_dict(self):
        func_name = getattr(self, f"as_dict_{self.msg_type}", self.as_dict_default)
        return func_name()

    def as_dict_default(self):
        return {
            "of_version": self.msg.header.version,
            "type": self.msg_type,
            "xid": self.msg_xid,
        }

    def as_dict_ofpt_flow_mod(self):
        return {
            "flags": self.msg.flags,
            "out_port": self.msg.out_port.value,
            "command": self.msg.command,
            "cookie": hex(self.msg.cookie.value),
            "cookie_mask": hex(self.msg.cookie_mask.value),
            "table_id": self.msg.table_id.value,
            "idle_timeout": self.msg.idle_timeout,
            "hard_timeout": self.msg.hard_timeout,
            "buffer_id": self.msg.buffer_id,
            "out_group": self.msg.out_group,
            "match": self.as_dict_match(),
            "instructions": self.as_dict_instructions(),
        }

    def as_dict_match(self):
        result = {
            "match_type": self.msg.match.match_type,
            "match_lengh": self.msg.match.length,
        }
        for oxm in self.msg.match.oxm_match_fields:
            result[str(oxm.oxm_field)] = str(oxm.oxm_value)
        return result

    def as_dict_instructions(self):
        ignore_inst_attrs = set(["instruction_type", "length", "pad"])
        result = []
        for instruction in self.msg.instructions:
            inst_name = InstructionType(instruction.instruction_type.value)
            inst_attrs = {"type": inst_name.name}
            for name, value in instruction.get_class_attributes():
                if name in ignore_inst_attrs:
                    continue
                if name == "actions":
                    inst_attrs["actions"] = [
                        self.as_dict_action(action) for action in value
                    ]
                else:
                    inst_attrs[name] = value
            result.append(inst_attrs)
        return result

    def as_dict_action(self, action):
        action_dict = {
            "type": action.action_type,
        }
        generic_attrs = set(["action_type", "length", "pad"])
        for name, value in  action.get_class_attributes():
            if name in generic_attrs:
                continue
            action_dict[name] = value
        return action_dict
