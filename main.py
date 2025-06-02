import sys
import asyncio
from switch import PyOFSwitch
from bfrt_controller import BfRtController

async def main():
    controller = BfRtController()
    controller.connect()
    s = PyOFSwitch(sys.argv[1], int(sys.argv[2]), controller = controller)
    controller.stream_wait_packets(s)
    controller.monitor_cpu_pcie_iface("ens1", s.callback_send_packet_in)
    await s.open_connection()

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
