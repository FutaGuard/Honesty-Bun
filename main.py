from typing import List

import httpx
import logging
import dns.asyncresolver
import dns.message
import asyncio
import pathlib

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

REDIRECT = {
    '165': '34.102.218.71',
    'TWNIC': '150.242.101.120'
}


def split_list(list_input) -> List[List[str]]:
    output_list = []
    for i in range(0, len(list_input), 5):
        output_list.append(list_input[i:i + min(5, len(list_input) - i)])
    return output_list


class Checker:
    def __init__(self):
        self.check_failed_file = pathlib.Path('./check_failed.txt')
        self.tmp: str = ''
        if not self.check_failed_file.exists():
            self.check_failed_file.touch()

    def write(self, domain: str):
        self.tmp += self.check_failed_file.read_text() + f'{domain}\n'
        self.check_failed_file.write_text(self.tmp)
        self.tmp = ''


class Bun:
    def __init__(self, cht_ip: str = '168.95.1.1'):
        self.filter_url = 'https://filter.futa.gg/TW165-domains.txt'
        self.cht_ip = cht_ip
        self.check = Checker()
        self.timedout: List[str] = []
        # self.bad: List[str] = []

    async def get_filter_list(self) -> List[str]:
        async with httpx.AsyncClient() as client:
            r = await client.get(self.filter_url)
            if r.status_code == 200:
                return r.text.splitlines()
            else:
                # logger.error('failed to get TW165.txt')
                raise Exception('failed to get TW165.txt')

    async def lookup(self, domain: str):
        q = dns.message.make_query(domain, 'A')
        try:
            r: dns.message.Message = await dns.asyncquery.udp(q, self.cht_ip, timeout=5)
        except dns.exception.Timeout:
            self.timedout.append(domain)
        except dns.query.BadResponse:
            # self.bad.append(domain)
            logger.error(f'[BadResponse] {domain}')
        else:
            if r.answer:
                ip = r.answer[0].to_text().split(' ')[-1]
                if ip in REDIRECT.values():
                    logger.info(f'[Redirect] {domain}')
                else:
                    logger.error(f'[NotRedirect] {domain}')
                    self.check.write(f'[NotRedirect] {domain}')
            else:
                self.check.write(f'[FailedResolve] {domain}')
                logger.error(f'[FailedResolve] {domain}')


async def main():
    bun = Bun()
    filterlist: List[List[str]] = split_list(await bun.get_filter_list())
    # tasking = []

    for bunch in filterlist:
        tasking = [bun.lookup(e) for e in bunch]
        await asyncio.gather(*tasking)

    retries = 3
    while bun.timedout and retries > 0:
        logger.info(f'Retrying ... {retries}')
        retrylist: List[List[str]] = split_list(bun.timedout)
        for domain in retrylist:
            tasking = [bun.lookup(e) for e in domain]
            await asyncio.gather(*tasking)
        retries -= 1


if __name__ == '__main__':
    asyncio.run(main())
