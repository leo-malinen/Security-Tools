import scrapy


class BlocklistItem(scrapy.Item):
    ip = scrapy.Field()
    source = scrapy.Field()
