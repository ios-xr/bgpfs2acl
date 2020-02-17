#!/usr/bin/env python

# Since /pkg/bin is not in default PYTHONPATH, the following
# two lines are necessary to be able to use the ztp_helper.py
# library on the box

import sys

sys.path.append("/pkg/bin/")

import os, subprocess
from ztp_helper import ZtpHelpers
import json, tempfile, time

ROOT_USER = "vagrant"
ROOT_USER_CREDENTIALS = "$1$FzMk$Y5G3Cv0H./q0fG.LGyIJS1"
ROOT_USER_CLEARTEXT = "vagrant"
SERVER_URL = "http://172.30.13.2:8079/"
SERVER_URL_PACKAGES = SERVER_URL + "/6225/"
SERVER_URL_SCRIPTS = SERVER_URL + "scripts/"
SERVER_URL_CONFIGS = SERVER_URL + "configs/"
CONFIG_FILES_MAP = {
    "FOC2137R1SL": "ncs5501-canonball.config",
    "FOC2137R1PU": "ncs5501-flamboyant.config",
    "FOC2128R078": "macrocarpa.config",
    "FOC2105R0JT": "red_pine.config",
    "8F0DG181C00": "AG9064-1.config",
    "AAC1845AACQ": "QuMX_1.config",
    "AAC1845AACD": "QuMX_2.config",
    "1843AAAD": "AS7816_1.config"
}


SYSLOG_SERVER = "172.30.13.13"
SYSLOG_PORT = 514
SYSLOG_LOCAL_FILE = "/root/ztp_python.log"

NODE_TYPE = ["Line Card",
             "LC",
             "Route Processor",
             "Route Switch Processor"]


class ZtpFunctions(ZtpHelpers):

    def set_root_user(self):
        """User defined method in Child Class
           Sets the root user for IOS-XR during ZTP

           Leverages xrapply() method in ZtpHelpers Class.

           :return: Return a dictionary with status and output
                    { 'status': 'error/success', 'output': 'output from xrapply' }
           :rtype: dict
        """
        config = """ !
                     username %s 
                     group root-lr
                     group cisco-support
                     secret 5 %s 
                     !
                     end""" % (ROOT_USER, ROOT_USER_CREDENTIALS)

        with tempfile.NamedTemporaryFile(delete=True) as f:
            f.write("%s" % config)
            f.flush()
            f.seek(0)
            result = self.xrapply(f.name)

        if result["status"] == "error":
            self.syslogger.info("Failed to apply root user to system %s" + json.dumps(result))

        return result

    def all_nodes_ready(self):
        """ Method to check if all nodes on the chassis are ready
            :return: Dictionary specifying success/error and an associated message
                     {'status': 'success/error',
                      'output':  True/False in case of success,
                                 error mesage in case of error}
            :rtype: dict
        """

        show_inventory = self.xrcmd({"exec_cmd": "show inventory | e PORT | i NAME:"})
        node_dict = {}

        if show_inventory["status"] == "success":
            try:
                for line in show_inventory["output"]:
                    if not any(tag in line for tag in ["NAME", "DESCR"]):
                        continue
                    str = '{' + line + '}'
                    str = str.replace("NAME", "\"NAME\"")
                    str = str.replace("DESCR", "\"DESCR\"")
                    if any(type in json.loads(str)['DESCR'] for type in NODE_TYPE):
                        node_dict[(json.loads(str)['NAME'])] = "inactive"
                        if self.debug:
                            self.logger.debug("Fetched Node inventory for the system")
                            self.logger.debug(node_dict)
            except Exception as e:
                if self.debug:
                    self.logger.debug("Error while fetching the node list from inventory")
                    self.logger.debug(e)
                return {"status": "error", "output": e}

            show_platform = self.xrcmd({"exec_cmd": "show platform"})

            if show_platform["status"] == "success":
                try:
                    for node in node_dict:
                        for line in show_platform["output"]:
                            if node + '/CPU' in line.split()[0]:
                                node_state = line.split()
                                xr_state = ' '.join(node_state[2:])
                                if 'IOS XR RUN' in xr_state:
                                    node_dict[node] = "active"
                except Exception as e:
                    if self.debug:
                        self.logger.debug("Error while fetching the XR status on node")
                        self.logger.debug(e)
                    return {"status": "error", "output": e}

            else:
                if self.debug:
                    self.logger.debug("Failed to get the output of show platform")
                return {"status": "error", "output": "Failed to get the output of show platform"}

        else:
            if self.debug:
                self.logger.debug("Failed to get the output of show inventory")
            return {"status": "error", "output": "Failed to get the output of show inventory"}

        if self.debug:
            self.logger.debug("Updated the IOS-XR state of each node")
            self.logger.debug(node_dict)

        if all(state == "active" for state in node_dict.values()):
            return {"status": "success", "output": True}
        else:
            return {"status": "success", "output": False}

    def wait_for_nodes(self, duration=600):
        """User defined method in Child Class
           Waits for all the linecards and RPs (detected in inventory)
           to be up before returning True.
           If 'duration' is exceeded, returns False.

           Use this method to wait for the system to be ready
           before installing packages or applying configuration.

           :param duration: Duration for which the script must
                            wait for nodes to be up.
                            Default Value is 600 seconds.
           :type duration: int

           :return: Returns a True or False
           :rtype: bool
        """
        nodes_up = False
        t_end = time.time() + duration
        while time.time() < t_end:
            nodes_check = self.all_nodes_ready()

            if nodes_check["status"] == "success":
                if nodes_check["output"]:
                    nodes_up = True
                else:
                    nodes_up = False

            else:
                self.syslogger.info("Failed to check if nodes are up, bailing out")
                self.syslogger.info(nodes_check["output"])

            if nodes_up:
                self.syslogger.info("All nodes up")
                return nodes_up
            else:
                self.syslogger.info("All nodes are not up")
                time.sleep(10)

        if not nodes_up:
            self.syslogger.info("All nodes did not come up, exiting")
            return nodes_up

    def xrreplace(self, filename=None):
        """Replace XR Configuration using a file

           :param file: Filepath for a config file
                        with the following structure:

                        !
                        XR config commands
                        !
                        end
           :type filename: str
           :return: Dictionary specifying the effect of the config change
                     { 'status' : 'error/success', 'output': 'exec command based on status'}
                     In case of Error:  'output' = 'show configuration failed'
                     In case of Success: 'output' = 'show configuration commit changes last 1'
           :rtype: dict
        """

        if filename is None:
            return {"status": "error", "output": "No config file provided for xrreplace"}

        status = "success"

        try:
            if self.debug:
                with open(filename, 'r') as config_file:
                    data = config_file.read()
                self.logger.debug("Config File content to be applied %s" % data)
        except Exception as e:
            return {"status": "error", "output": "Invalid config file provided"}

        cmd = "source /pkg/bin/ztp_helper.sh && xrreplace " + filename

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        out, err = process.communicate()

        # Check if the commit failed

        if process.returncode:
            ## Config commit failed.
            status = "error"
            exec_cmd = "show configuration failed"
            config_failed = self.xrcmd({"exec_cmd": exec_cmd})
            if config_failed["status"] == "error":
                output = "Failed to fetch config failed output"
            else:
                output = config_failed["output"]

            if self.debug:
                self.logger.debug("Config replace through file failed, output = %s" % output)
            return {"status": status, "output": output}
        else:
            ## Config commit successful. Let's return the last config change
            exec_cmd = "show configuration commit changes last 1"
            config_change = self.xrcmd({"exec_cmd": exec_cmd})
            if config_change["status"] == "error":
                output = "Failed to fetch last config change"
            else:
                output = config_change["output"]

            if self.debug:
                self.logger.debug("Config replace through file successful, last change = %s" % output)
            return {"status": status, "output": output}

    def run_bash(self, cmd=None):
        """User defined method in Child Class
           Wrapper method for basic subprocess.Popen to execute
           bash commands on IOS-XR.

           :param cmd: bash command to be executed in XR linux shell.
           :type cmd: str

           :return: Return a dictionary with status and output
                    { 'status': '0 or non-zero',
                      'output': 'output from bash cmd' }
           :rtype: dict
        """
        ## In XR the default shell is bash, hence the name
        if cmd is not None:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            out, err = process.communicate()
        else:
            self.syslogger.info("No bash command provided")

        status = process.returncode

        return {"status": status, "output": out}


if __name__ == "__main__":

    # Create an Object of the child class, syslog parameters are optional.
    # If nothing is specified, then logging will happen to local log rotated file.

    ztp_script = ZtpFunctions(syslog_file=SYSLOG_LOCAL_FILE, syslog_server=SYSLOG_SERVER, syslog_port=SYSLOG_PORT)

    ztp_script.syslogger.info("###### Starting ZTP RUN on NCS5508 ######")

    # Enable verbose debugging to stdout/console. By default it is off
    ztp_script.toggle_debug(1)

    # Change context to XR VRF in the linux shell when needed. Depends on when user changes config to create network namespace.

    # No Config applied yet, so start with global-vrf(default)"
    ztp_script.set_vrf("global-vrf")

    # Set the root user first. Always preferable so that the user can manually gain access to the router in case ZTP script aborts.
    ztp_script.set_root_user()

    # Let's wait for inventory manager to be updated before checking if nodes are ready

    # Wait for all nodes (linecards, standby etc.)  to be up before installing packages
    # Check for a user defined maximum (time in seconds)
    if ztp_script.wait_for_nodes(600):
        ztp_script.syslogger.info("All Nodes are up!")
    else:
        ztp_script.syslogger.info("Nodes did not come up! Continuing")
        # sys.exit(1)

    # # Install crypto keys
    show_pubkey = ztp_script.xrcmd({"exec_cmd": "show crypto key mypubkey rsa"})

    if show_pubkey["status"] == "success":
        if show_pubkey["output"] == '':
            ztp_script.syslogger.info("No RSA keys present, Creating...")
            ztp_script.xrcmd({"exec_cmd": "crypto key generate rsa", "prompt_response": "2048\\n"})
        else:
            ztp_script.syslogger.info("RSA keys already present, Recreating....")
            ztp_script.xrcmd({"exec_cmd": "crypto key generate rsa", "prompt_response": "yes\\n 2048\\n"})
    else:
        ztp_script.syslogger.info("Unable to get the status of RSA keys: " + str(show_pubkey["output"]))
        # Not quitting the script because of this failure

    serial_cmd = "grep -a CHASSIS_SERIAL_NUMBER= /dev/xr_bootstrap | cut -d \'=\' -f 2"
    serial_number = ztp_script.run_bash(serial_cmd)

    CONFIG_FILE = CONFIG_FILES_MAP[serial_number["output"].rstrip()]

    # Download Config with Mgmt vrfs
    output = ztp_script.download_file(SERVER_URL_CONFIGS + CONFIG_FILE, destination_folder="/root/")

    if output["status"] == "error":
        ztp_script.syslogger.info("Config Download failed, Abort!")
        sys.exit(1)

    ztp_script.syslogger.info("Replacing system config with the downloaded config")
    # Replace existing config with downloaded config file
    config_apply = ztp_script.xrreplace("/root/" + CONFIG_FILE)

    if config_apply["status"] == "error":
        ztp_script.syslogger.info("Failed to replace existing config")
        ztp_script.syslogger.info("Config Apply result = %s" % config_apply["output"])
        try:
            os.remove("/root/" + CONFIG_FILE)
        except OSError:
            ztp_script.syslogger.info("Failed to remove downloaded config file")

    # VRFs on Mgmt interface are configured by user. Use the set_vrf helper method to set proper
    # context before continuing.
    # Syslog and download operations are covered by the set vrf utility by default.
    # For any other shell commands that utilize the network,
    # change context to vrf using `ip netns exec <vrf>` before the command

    ztp_script.set_vrf("global-vrf")
    ztp_script.syslogger.info("###### Changed context to user specified VRF based on config ######")
    ztp_script.syslogger.info("Base config applied successfully")
    ztp_script.syslogger.info("Config Apply result = %s" % config_apply["output"])

    ztp_script.syslogger.info("ZTP complete!")
    sys.exit(0)
