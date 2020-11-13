from errbot import BotPlugin
import os
import json
import requests
import redis
from datetime import datetime


class Urlscanmonitor(BotPlugin):
    """
    Look for domains and IPs on various blacklists
    """

    def send_to_slack(self, results):
        r = redis.from_url(os.environ.get("REDIS_URL"))
        timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        for result in results:
            scan_url = result['page']['url']
            result_url = result['result']
            try:
                if not r.get(scan_url):
                    r.set(scan_url, timestamp)
                    message = 'Found URL: <{}|{}> in URLScan'.format(result_url, scan_url)
                    if scan_url.starswith('https://airtable.com/'):
                        message = 'Found *Airtable* URL: <{}|{}> in URLScan'.format(result_url, scan_url)
                    self.send(self.build_identifier("#security-dev-bot"), message,)
            except Exception as e:
                self.log.info("Error sending message for: {} - {}".format(result_url, e))


    def find_sites(self):
        DOMAINS = os.getenv("URLSCAN_DOMAINS")
        headers = {'User-Agent': 'Security Monitor Bot'}
        domains = list()

        self.log.info('Waking up to monitor for IPs and Domains')
        if DOMAINS is not None and DOMAINS != "":
            domains = [domain.strip() for domain in DOMAINS.split(",")]

        self.log.info("Monitoring Domains: {}".format(", ".join(domains)))
        for domain in domains:
            try:
                query = 'domain:{}'.format(domain)
                payload = {'q': query}
                r = requests.get(
                    "https://urlscan.io/api/v1/search/",
                    params=payload,
                    headers=headers
                )
                if r.status_code == 200:
                    self.send_to_slack(json.loads(r.text))
            except Exception as e:
                self.log.info("Error requesting domain ({}) check: {}".format(domain, e))


    def activate(self):
        poll_minutes = int(os.getenv("URLSCAN_POLL_MINUTES"))
        super().activate()
        self.start_poller(60 * poll_minutes, self.find_sites)
