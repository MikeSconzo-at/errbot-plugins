from errbot import BotPlugin
import os
import json
import requests


class Virustotalmonitor(BotPlugin):
    """
    Look for domains and IPs on various blacklists
    """


    def send_to_slack(self, results):
        lists = list()
        if 'positives' in results and results['positives'] > 0:
            if 'scans' in results:
                for r in results['scans']:
                    if results['scans'][r]['detected']:
                        lists.append(r)
            self.send(
                self.build_identifier(os.getenv('VT_SLACK_CHANNEL')),
                "{} Appears in {} Blacklists\n see details in *<{}|VirusTotal>*".format(
                    results["resource"],
                    results["positvies"],
                    results["permalink"]),)


    def check_lists(self):
        IPS = os.getenv("VT_IPS")
        DOMAINS = os.getenv("VT_DOMAINS")
        APIKEY = os.getenv("VT_APIKEY")
        headers = {'User-Agent': 'Security Monitor Bot'}
        ips = list()
        domains = list()

        self.log.info('Waking up to monitor for IPs and Domains')
        if IPS is not None and IPS != "":
            ips = [ip.strip() for ip in IPS.split(",")]
        if DOMAINS is not None and DOMAINS != "":
            domains = [domain.strip() for domain in DOMAINS.split(",")]

        indicators = ips + domains

        self.log.info("Monitoring IPs: {}".format(", ".join(ips)))
        self.log.info("Monitoring Domains: {}".format(", ".join(domains)))
        for i in indicators:
            try:
                r = requests.get(
                    "https://www.virustotal.com/vtapi/v2/url/report?apikey={}&resource={}".format(
                        APIKEY, i
                    ),
                    headers=headers
                )
                if r.status_code == 200:
                    self.send_to_slack(json.loads(r.text))
            except Exception as e:
                self.log.info("Error requesting ip ({}) check: {}".format(i, e))


    def scan_indicators(self):
        IPS = os.getenv("VT_IPS")
        DOMAINS = os.getenv("VT_DOMAINS")
        APIKEY = os.getenv("VT_APIKEY")
        headers = {'User-Agent': 'Security Monitor Bot'}
        data = {'apikey': APIKEY}
        ips = list()
        domains = list()

        self.log.info('Waking up to monitor for IPs and Domains')
        if IPS is not None and IPS != "":
            ips = [ip.strip() for ip in IPS.split(",")]
        if DOMAINS is not None and DOMAINS != "":
            domains = [domain.strip() for domain in DOMAINS.split(",")]

        indicators = ips + domains

        self.log.info("Scanning IPs: {}".format(", ".join(ips)))
        self.log.info("Scanning Domains: {}".format(", ".join(domains)))
        for i in indicators:
            try:
                data['url'] = i
                r = requests.post(
                    "https://www.virustotal.com/vtapi/v2/url/scan",
                    headers=headers,
                    data=data
                )
                if r.status_code == 200:
                    self.send_to_slack(json.loads(r.text))
            except Exception as e:
                self.log.info("Error requesting ip ({}) check: {}".format(i, e))


    def activate(self):
        poll_minutes = int(os.getenv("VT_POLL_MINUTES"))
        super().activate()
        self.start_poller(60 * poll_minutes, self.check_lists)
        self.start_poller(60 * 60 * 24, self.scan_indicators)
