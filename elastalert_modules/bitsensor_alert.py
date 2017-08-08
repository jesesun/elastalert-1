from elastalert.alerts import Alerter, SlackAlerter, BasicMatchString, DateTimeEncoder
from elastalert.util import lookup_es_key
from elastalert.util import EAException
from elastalert.util import elastalert_logger

from texttable import Texttable
from requests.exceptions import RequestException
import requests
import json

# This alerter modifies Aggregation summary text as the following example:
#
# context.ip      count
# -----------------------
# 111.111.211.211   4    
# 111.211.211.311   1    

#                      context.http.userAgent                          count
# ---------------------------------------------------------------------------
# python-requests/2.12.3                                                1    
# Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1   4    

# detections_parsed.type   count
# ------------------------------
# csrf                     1    
# discovery                4
class BitSensorAlerter(Alerter):
    def create_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            if len(matches) > 1:
                body += '\n'
        return body

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]

            for key in summary_table_fields:
                match_aggregation = {}

                values = [unicode(lookup_es_key(match, key)) for match in matches]

                for value in values:
                    if value not in match_aggregation:
                        match_aggregation[value] = 1
                    else:
                        match_aggregation[value] += 1

                table = Texttable(0)
                table.set_deco(Texttable.HEADER)
                table.set_chars(['','','','-'])
                table.set_cols_align(["l", "l"])
                table.header([key, 'count'])

                for key, count in match_aggregation.iteritems():
                    table.add_row([key] + [count])
                text += table.draw() + '\n\n' 

        return unicode(text)

class BitSensorSlackAlerter(BitSensorAlerter):
    """ Creates a Slack room message for each alert """
    required_options = frozenset(['slack_webhook_url'])

    def __init__(self, rule):
        super(BitSensorSlackAlerter, self).__init__(rule)
        self.slack_webhook_url = self.rule['slack_webhook_url']
        if isinstance(self.slack_webhook_url, basestring):
            self.slack_webhook_url = [self.slack_webhook_url]
        self.slack_proxy = self.rule.get('slack_proxy', None)
        self.slack_username_override = self.rule.get('slack_username_override', 'elastalert')
        self.slack_channel_override = self.rule.get('slack_channel_override', '')
        self.slack_emoji_override = self.rule.get('slack_emoji_override', ':ghost:')
        self.slack_icon_url_override = self.rule.get('slack_icon_url_override', '')
        self.slack_msg_color = self.rule.get('slack_msg_color', 'danger')
        self.slack_parse_override = self.rule.get('slack_parse_override', 'none')
        self.slack_text_string = self.rule.get('slack_text_string', '')

    def format_body(self, body):
        # https://api.slack.com/docs/formatting
        body = body.encode('UTF-8')
        body = body.replace('&', '&amp;')
        body = body.replace('<', '&lt;')
        body = body.replace('>', '&gt;')
        return body

    def alert(self, matches):
        body = self.create_alert_body(matches)

        body = self.format_body(body)
        # post to slack
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.slack_proxy} if self.slack_proxy else None
        payload = {
            'username': self.slack_username_override,
            'channel': self.slack_channel_override,
            'parse': self.slack_parse_override,
            'text': self.slack_text_string,
            'attachments': [
                {
                    'color': self.slack_msg_color,
                    'title': self.create_title(matches),
                    'text': body,
                    'mrkdwn_in': ['text', 'pretext'],
                    'fields': []
                }
            ]
        }
        if self.slack_icon_url_override != '':
            payload['icon_url'] = self.slack_icon_url_override
        else:
            payload['icon_emoji'] = self.slack_emoji_override

        for url in self.slack_webhook_url:
            try:
                response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting to slack: %s" % e)
        elastalert_logger.info("Alert sent to Slack")

    def get_info(self):
        return {'type': 'slack',
                'slack_username_override': self.slack_username_override,
                'slack_webhook_url': self.slack_webhook_url}
    