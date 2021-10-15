
# encoding = utf-8
# Always put this line at the beginning of this file
import cyences_custom_alert_action_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_cyences_alert_action_helper

class AlertActionWorkercyences_alert_action(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkercyences_alert_action, self).__init__(ta_name, alert_name)

    def validate_params(self):
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_cyences_alert_action_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkercyences_alert_action("TA-custom_alert_action", "cyences_alert_action").run(sys.argv)
    sys.exit(exitcode)