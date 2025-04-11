import asyncio
from utils import GenericHello, of_slicer
from pyof.v0x04.symmetric.hello import Hello
from pyof.utils import unpack

class PyOFSwitch:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None
        self.is_connected = False
        self.is_new_connection = None
        self.loop = asyncio.get_running_loop()

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
        try:
            hello = Hello()
            packet = hello.pack()
            self.writer.write(packet)
            await self.writer.drain()
        except Exception as err:
            print(f'Invalid hello message: {err}')
            return False
        return True
    
    async def open_connection(self,):
        print("Opening OF Controller...")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.is_connected = True
        self.is_new_connection = True
        self.send_hello()
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
                print(
                    'Connection IN OFP, ver: %s, type: %s, xid: %s',
                    message.header.version,
                    message.header.message_type,
                    message.header.xid
                )
        print("connection closed")
        self.is_connected = False
        # TODO: finish writer

