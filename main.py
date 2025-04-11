import asyncio
from switch import PyOFSwitch

async def main():
    s = PyOFSwitch("127.0.0.1", 8888)
    await s.open_connection()

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
