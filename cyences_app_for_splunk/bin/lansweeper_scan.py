import json
import splunk.admin as admin
from splunk import rest


CONF_FILE = 'cs_configurations'
LANSWEEPER_SCAN_STANZA = 'lansweeper_scan'


class DoLansweeperScanRestcall(admin.MConfigHandler):
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
            api_url = None
            password = None
            for i in data:
                if i['name'] == LANSWEEPER_SCAN_STANZA:
                    api_url = i['content']['api_url']
                    password = i['content']['password']
                    break

            # TODO - Make Lansweeper API call and get scan result and pass it through conf_info['lansweeper']['scan_result'] variable to the client.
            # Add conf_info['lansweeper']['error'] in case of error from Lansweeper scan

        except Exception as e:
            conf_info['lansweeper']['error'] = 'Unable to make lansweeper scan. {}'.format(e)


if __name__ == "__main__":
    admin.init(DoLansweeperScanRestcall, admin.CONTEXT_APP_AND_USER)
