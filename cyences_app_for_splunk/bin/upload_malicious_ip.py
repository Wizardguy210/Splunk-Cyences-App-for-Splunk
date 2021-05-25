#!/usr/bin/env python

import sys
import json
import requests


from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option
from splunklib.searchcommands.validators import Code
from splunk import rest
import cs_utils


CONF_FILE = 'cs_configurations'


@Configuration()
class MaliciousIPUploaderCommand(EventingCommand):

    def get_api_info(self):
        sessionKey = self.search_results_info.auth_token
        _, serverContent = rest.simpleRequest("/servicesNS/nobody/cyences_app_for_splunk/configs/conf-{}?output_mode=json".format(CONF_FILE), sessionKey=sessionKey)
        data = json.loads(serverContent)['entry']
        api_url = ''
        for i in data:
            if i['name'] == 'maliciousip':
                api_url = i['content']['api_url']
                auth_token = cs_utils.CredentialManager(sessionKey).get_credential(api_url)
                break
        return {'api_url': api_url, 'auth_token': auth_token}
    

    def transform(self, records):
        api_payload = []
        api_config = self.get_api_info()

        if not api_config['api_url'] or not api_config['auth_token']:
            self.logger.error("MaliciousIP Collector Configuration not found in the cs_configurations.conf file.")
            raise Exception("API URL and Authentication Token not set. Please navigate to Cyences App > Configuration page to do so.")

        for record in records:
            api_payload.append(
                {
                    'ip': record['ip'],
                    'ip_location': ','.join(record['ip_location']) if type(record['ip_location']) == list else str(record['ip_location']),
                    'device': ','.join(record['dvc']) if type(record['dvc']) == list else str(record['dvc']),
                    'category': str(record['ip_category']),
                    'last_seen': float(record['last_seen']),
                }
            )
        endpoint_url = "{}/api/v1/firewall_mal_ips/add".format(api_config['api_url'].rstrip('/'))
        payload = {'data': api_payload}
        auth_header = {
            "Authorization": "Bearer {}".format(api_config['auth_token'])
        }
        resp = None
        try:
            resp = requests.post(endpoint_url, json=payload, headers=auth_header)
            resp.raise_for_status()
            yield {'success': True, 'message': "Successfully Uploaded Ips to API."}
            self.logger.info("Response received {}".format(resp.json()))
        except Exception as e:
            if resp:
                yield {
                    'success': False,
                    'error_message': "Failed to upload Ips to API, Reason {}".format(repr(e)),
                    'response_body': resp.json()
                }
            else:
                yield {
                    'success': False,
                    'error_message': "Failed to upload Ips to API, Reason {}".format(repr(e)),
                    'response': "None"
                }
        

dispatch(MaliciousIPUploaderCommand, sys.argv, sys.stdin, sys.stdout, __name__)