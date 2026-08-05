import re

import scrapy

from netmon.feeds.items import BlocklistItem

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")


class BlocklistSpider(scrapy.Spider):
    name = "blocklist"

    def __init__(self, urls=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [u for u in (urls or "").split(",") if u.strip()]

    def parse(self, response):
        source = response.url
        for raw in response.text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            candidate = line.split()[0].split(";")[0].strip()
            if IP_PATTERN.match(candidate):
                yield BlocklistItem(ip=candidate.split("/")[0], source=source)


class ThreatPageSpider(scrapy.Spider):
    name = "threatpage"

    def __init__(self, urls=None, selector="body", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [u for u in (urls or "").split(",") if u.strip()]
        self.selector = selector

    def parse(self, response):
        text = " ".join(response.css(self.selector + " ::text").getall())
        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            yield BlocklistItem(ip=match, source=response.url)
