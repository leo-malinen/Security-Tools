import os

from netmon.storage import Storage


class SqlitePipeline:
    def __init__(self, database):
        self.database = database
        self.storage = None
        self.batch = []

    @classmethod
    def from_crawler(cls, crawler):
        database = crawler.settings.get("NETMON_DATABASE") or os.environ.get(
            "NETMON_DATABASE", "netmon.db"
        )
        return cls(database)

    def open_spider(self, spider):
        self.storage = Storage(self.database)

    def close_spider(self, spider):
        if self.batch:
            self.storage.replace_blocklist(self.batch)
            self.batch = []
        self.storage.close()

    def process_item(self, item, spider):
        self.batch.append((item["ip"], item.get("source", spider.name)))
        if len(self.batch) >= 500:
            self.storage.replace_blocklist(self.batch)
            self.batch = []
        return item
