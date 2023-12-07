import httpx
import logging
import dns.asyncresolver
import dns.message
import asyncio

logger = logging.getLogger(__name__)


class Bun:
    def __init__(self, cht_ip: str = '168.95.1.1'):
        self.filter_url = 'https://filter.futa.gg/TW165.txt'
        self.cht_ip = cht_ip

    async def get_filter_list(self) -> str:
        async with httpx.AsyncClient() as client:
            r = await client.get(self.filter_url)
            if r.status_code == 200:
                return r.text
            else:
                # logger.error('failed to get TW165.txt')
                raise Exception('failed to get TW165.txt')

    async def lookup(self, domain: str) -> bool:
        q = dns.message.make_query(domain, 'A')
        r: dns.message.Message = await dns.asyncquery.udp(q, self.cht_ip)
        if r.answer:
            ip = r.answer[0].to_text().split(' ')[-1]
            if ip == '34.102.218.71':
                return True
        return False


if __name__ == '__main__':
    bun = Bun()
    asyncio.run(bun.lookup('tw11st.com'))
    # todo!
    # - [ ] read list and chunks
    # - [ ] run with gather in task