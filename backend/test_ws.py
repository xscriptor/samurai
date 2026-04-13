import asyncio
import websockets

async def test():
    async with websockets.connect("ws://127.0.0.1:8000/api/vuln/live?target=scanme.nmap.org") as ws:
        async for msg in ws:
            print("Received:", msg)

asyncio.run(test())
