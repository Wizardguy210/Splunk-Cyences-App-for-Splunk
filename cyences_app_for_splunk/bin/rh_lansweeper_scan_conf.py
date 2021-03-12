import json
import splunk.admin as admin
from splunk import rest
import cs_utils
import uuid

CONF_FILE = 'cs_configurations'
LANSWEEPER_SCAN_STANZA = 'lansweeper_scan'


class LansweeperScanRestcall(admin.MConfigHandler):
    '''
    Set up supported arguments
    '''

    # Static variables
    def setup(self):
        """
        Sets the input arguments
        :return:
        """
        # Set up the valid parameters
        for arg in ['data']:
            self.supportedArgs.addOptArg(arg)


    def handleList(self, conf_info):
        # Get MaliciousIP Collector Configuration
        try:
            _, serverContent = rest.simpleRequest("/servicesNS/nobody/cyences_app_for_splunk/configs/conf-{}?output_mode=json".format(CONF_FILE), sessionKey=self.getSessionKey())
            data = json.loads(serverContent)['entry']
            api_url = ''
            password = '******'
            for i in data:
                if i['name'] == LANSWEEPER_SCAN_STANZA:
                    api_url = i['content']['api_url']
                    break
            conf_info['action']['api_url'] = api_url
            conf_info['action']['password'] = password
        except Exception as e:
            conf_info['action']['error'] = 'Unable to fetch the Lansweeper configuration. Might be no existing configuration present. {}'.format(e)
    

    def handleEdit(self, conf_info):
        # Update the MaliciousIP Collector configuration
        try:
            data = json.loads(self.callerArgs['data'][0])
        except Exception as e:
            conf_info['action']['error'] = 'Data is not in proper format. {} - {}'.format(e, self.callerArgs["data"])
            return

        try:
            # Store API ID
            rest.simpleRequest("/servicesNS/nobody/cyences_app_for_splunk/configs/conf-{}/{}?output_mode=json".format(CONF_FILE, LANSWEEPER_SCAN_STANZA), postargs={'api_url': api_url}, method='POST', sessionKey=self.getSessionKey())
            _, serverContent = rest.simpleRequest("/servicesNS/nobody/cyences_app_for_splunk/configs/conf-{}?output_mode=json".format(CONF_FILE), sessionKey=self.getSessionKey())
            data = json.loads(serverContent)['entry']
            cust_id = ''
            for i in data:
                if i['name'] == LANSWEEPER_SCAN_STANZA:
                    cust_id = i['content'].get('cust_id','')
                    if cust_id == '':
                        rest.simpleRequest("/servicesNS/nobody/cyences_app_for_splunk/configs/conf-{}/{}?output_mode=json".format(CONF_FILE, LANSWEEPER_SCAN_STANZA), postargs={'cust_id': uuid.uuid4().hex}, method='POST', sessionKey=self.getSessionKey())
            # TODO - Need to get required fields
            # Store API Key
            cs_utils.CredentialManager(self.getSessionKey()).store_credential(api_url, password)

            conf_info['action']['success'] = "Lansweeper configuration is stored successfully."

        except Exception as e:
            conf_info['action']['error'] = 'No success or error message returned. {}'.format(e)


if __name__ == "__main__":
    admin.init(LansweeperScanRestcall, admin.CONTEXT_APP_AND_USER)
