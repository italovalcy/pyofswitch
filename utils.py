import struct
import config

def of_slicer(remaining_data):
    """Slice a raw `bytes` instance into OpenFlow packets."""
    data_len = len(remaining_data)
    pkts = []
    while data_len > 3:
        length_field = struct.unpack('!H', remaining_data[2:4])[0]
        ofver = remaining_data[0]
        # sanity checks: badly formatted packet
        if ofver not in config.OPENFLOW_VERSIONS or length_field == 0:
            remaining_data = remaining_data[4:]
            data_len = len(remaining_data)
            continue
        if data_len >= length_field:
            pkts.append(remaining_data[:length_field])
            remaining_data = remaining_data[length_field:]
            data_len = len(remaining_data)
        else:
            break
    return pkts, remaining_data
