import requests
import json
import time
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
class Webhook:
    def __init__(self):
        """
            Initialise Slack API token
        """
        self.webhook = "https://hooks.slack.com/services/xx/xx/xx"

    def alert(self, s_rule, s_text, s_priority, s_source):
        """
            Send alert to Slack using Incoming Webhook
        """
        s_ts = time.mktime(datetime.now().timetuple())
        s_color = "danger"
        payload = {
                "attachments": [
                    { 
                        "fallback": "Jupyter",
                        "color": "danger",
                        "title": "ALERT",
                        "text": s_text,
                        "fields": [
                            {
                                "title": "Rule",
                                "value": s_rule,
                                "short": "true"
                            },
                            {
                                "title": "Priority",
                                "value": s_priority,
                                "short": "true"
                            },
                            {
                                "title": "Type",
                                "value": "Jupyter",
                                "short": "true"
                            },
                            {
                                "title": "Source",
                                "value": s_source,
                                "short": "true"
                            }
                        ],
                        "footer": "Jupyter",
                        "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                        "ts": s_ts                 
                    } 
                ]
        }
        r = requests.post(self.webhook, data=json.dumps(payload))