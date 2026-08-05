import time

from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

from netmon.feeds.spiders.blocklist_spider import BlocklistSpider


def run_feed_refresh(database, sources):
    if not sources:
        return 0
    settings = get_project_settings()
    settings.setmodule("netmon.feeds.settings", priority="project")
    settings.set("NETMON_DATABASE", database, priority="cmdline")
    process = CrawlerProcess(settings)
    process.crawl(BlocklistSpider, urls=",".join(sources))
    process.start()
    return len(sources)


def should_refresh(storage, hours):
    last = float(storage.get_state("feeds_last_refresh", 0) or 0)
    return time.time() - last >= hours * 3600


def mark_refreshed(storage):
    storage.set_state("feeds_last_refresh", time.time())
