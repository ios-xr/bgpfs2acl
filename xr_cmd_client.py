import re
from pprint import pformat

import paramiko

import logging

logger = logging.getLogger(__name__)


class XRCmdExecError(StandardError):
    pass


class XRCmdClient:
    def __init__(self, user, password='', host='127.0.0.1', port='57722'):

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        look_for_keys, allow_agent = True, True

        if password:
            look_for_keys, allow_agent = False, False

        self.ssh.connect(
            host,
            username=user,
            password=password,
            port=int(port),
            look_for_keys=look_for_keys,
            allow_agent=allow_agent
        )
        channel = self.ssh.invoke_shell()
        self.stdin = channel.makefile('wb')
        self.stdout = channel.makefile('r')

        # this output was made for cleaning stdout out of info about established ssh connection
        ready_msg = 'connected succesfully'
        self.stdin.write('echo {}\n'.format(ready_msg))
        for line in self.stdout:
            if line.startswith(ready_msg):
                break

    def __del__(self):
        self.ssh.close()

    @staticmethod
    def _print_exec_out(cmd, out_buf):
        logger.info('XR command executed: {}'.format(cmd))
        if out_buf:
            logger.info('OUTPUT:')
            logger.info(pformat(out_buf))
            logger.info('end of OUTPUT')

    def _exec_xr_func(self, xr_func, xr_arg):
        """
        Execute xr command through the ssh using channel
        :param xr_func: xr function from ztp_helper.sh (xrcmd or xrapply_string)
        :param xr_arg: argument string being passed to an xr function
        :return:
        :raises: XRCmdExecError due to failure
        """
        xr_arg = xr_arg.strip('\n')
        cmd = 'sudo su - root -c "source /pkg/bin/ztp_helper.sh && {func} \'{arg}\'"'.format(func=xr_func, arg=xr_arg)
        self.stdin.write(''.join([cmd, '\n']))
        finish = 'end of stdOUT buffer. finished with exit status'
        echo_cmd = 'echo {} $?'.format(finish)
        self.stdin.write(echo_cmd + '\n')
        self.stdin.flush()

        output = []
        exit_status = 0
        for line in self.stdout:
            if str(line).startswith(cmd) or str(line).startswith(echo_cmd):
                # up for now filled with shell junk from stdin
                output = []
            elif str(line).startswith(finish):
                # our finish command ends with the exit status
                exit_status = int(str(line).rsplit(None, 1)[1])
                break
            elif line.isspace():
                continue
            else:
                # get rid of 'coloring and formatting' special characters
                output.append(re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).
                              replace('\b', '').replace('\r', '').strip())

        # first and last lines of output contain a prompt
        # join/split need because xr returns whitespace after 80th symbol
        if output and ''.join(echo_cmd.split()) in ''.join(output[-1].split()):
            output.pop()
        if output and ''.join(cmd.split()) in ''.join(output[0].split()):
            output.pop(0)

        # xrapply_string returns 1 due to failure, xrcmd returns 0, but has a pattern in first line
        if exit_status or (output and output[0].startswith('showtech_helper error:')):
            raise XRCmdExecError(pformat(output))

        self._print_exec_out(cmd=cmd, out_buf=output)
        return output

    def xrcmd(self, arg_str):
        return self._exec_xr_func('xrcmd', arg_str)

    def xrapply_string(self, arg_str):
        return self._exec_xr_func('xrapply_string', arg_str)
