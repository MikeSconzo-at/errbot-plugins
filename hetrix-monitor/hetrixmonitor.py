from errbot import BotPlugin
import os
import json
import requests


class Hetrixmonitor(BotPlugin):
    """
    Look for domains and IPs on various blacklists
    """

    #def get_configuration_template(self):
    #    """
    #    Defines the configuration structure this plugin supports
    #
    #    You should delete it if your plugin doesn't use any configuration like this
    #    """
    #    return {'EXAMPLE_KEY_1': "Example value",
    #            'EXAMPLE_KEY_2': ["Example", "Value"]
    #           }


    def send_to_slack(self, results):
        if ("Blacklisted_Count" in results) and (results["Blacklisted_Count"] > 0):
            lists = [blklist["RBL"] for blklist in results["Blacklisted_On"]]
            self.send(
                self.build_identifier("#abuse-bot"),
                "{} Appears in {} Blacklists\n see details in *<{}|HetrixTools>*".format(
                    results["Target"],
                    results["Blacklisted_Count"],
                    results["Links"]["Report_Link"]),)


    def check_lists(self):
            IPS = os.getenv("HETRIX_IPS")
            DOMAINS = os.getenv("HETRIX_DOMAINS")
            APIKEY = os.getenv("HETRIX_APIKEY")
            ips = list()
            domains = list()

            self.log.info('Waking up to monitor for IPs and Domains')
            if IPS is not None and IPS != "":
                ips = [ip.strip() for ip in IPS.split(",")]
            if DOMAINS is not None and DOMAINS != "":
                domains = [domain.strip() for domain in DOMAINS.split(",")]

            self.log.info("Monitoring IPs: {}".format(", ".join(ips)))
            self.log.info("Monitoring Domains: {}".format(", ".join(domains)))
            for ip in ips:
                try:
                    r = requests.get(
                        "https://api.hetrixtools.com/v2/{}/blacklist/report/{}/".format(
                            APIKEY, ip
                        )
                    )
                    if r.status_code == 200:
                        self.send_to_slack(json.loads(r.text))
                except Exception as e:
                    self.log.info("Error requesting ip ({}) check: {}".format(ip, e))

            for domain in domains:
                try:
                    r = requests.get(
                        "https://api.hetrixtools.com/v2/{}/blacklist/report/{}/".format(
                            APIKEY, domain
                        )
                    )
                    if r.status_code == 200:
                        self.send_to_slack(json.loads(r.text))
                except Exception as e:
                    self.log.info("Error requesting domain ({}) check: {}".format(domain, e))


    def activate(self):
        poll_minutes = int(os.getenv("HETRIX_POLL_MINUTES"))
        super().activate()
        self.start_poller(60 * poll_minutes, self.check_lists)
