"""CiscoBaseConnection is netmiko SSH class for Cisco and Cisco-like platforms."""
import re
import time
from typing import Collection, Union

from scrapli.driver.core.cisco_iosxe.base_driver import FAILED_WHEN_CONTAINS
from scrapli.driver.generic.base_driver import BaseGenericDriver
from scrapli.response import (
    MultiResponse,
    Response,
)

from netmiko.base_connection import BaseConnection
from netmiko.scp_handler import BaseFileTransfer
from netmiko.ssh_exception import NetmikoAuthenticationException


class ConfigCommandResponse(Response):
    def __repr__(self) -> str:
        """
        Magic repr method for Response class

        Args:
            N/A

        Returns:
            str: repr for class object

        Raises:
            N/A

        """
        return f"ConfigCommandResponse <Success: {str(not self.failed)}>"

    def __str__(self) -> str:
        """
        Magic str method for Response class

        Args:
            N/A

        Returns:
            str: str for class object

        Raises:
            N/A

        """
        return f"ConfigCommandResponse <Success: {str(not self.failed)}>"

    def console_output(self) -> str:
        """Display's what the console output would have looked like.

        An exmaple of console output would be:

        '''
        cisco-ios-device# show run | inc booted
        boot system switch all flash:cat9k_iosxe.16.10.01.SPA.conf
        license boot level network-advantage addon dna-advantage
        '''

        diagnostic bootup level minimal
        Args:
            N/A

        Returns:
            string of what the original prompt, input, and outputu would have
            looked like in the console.

        Raises:
            N/A

        """
        console_output = f"{self.initial_prompt}{self.channel_input}\n"
        if self.failed and self.result:
            console_output += f"{self.result}\n"

        return console_output


class CiscoBaseConnection(BaseConnection):
    """Base Class for cisco-like behavior."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._base_prompt = f"{self.base_prompt}#"
        self.failed_when_contains = FAILED_WHEN_CONTAINS

    @staticmethod
    def _enter_config_mode_command(command):
        return "conf" in command and " t" in command

    @staticmethod
    def _exit_config_mode_command(command):
        command = command.strip()

        return "end" == command

    @staticmethod
    def _parse_output(output, command, prompt):
        result = ""
        try:
            __, raw_result = output.split(command)

            result = raw_result.replace(prompt, "")
            result = result.strip()
        except ValueError:
            pass

        return result

    @staticmethod
    def _prepare_result(response, response_prompt, result,
                        raw_result=b""):

        resp = BaseGenericDriver._post_send_command(
                raw_response=raw_result,
                processed_response=result.encode(),
                response=response,
                response_prompt=response_prompt)
        return resp

    def _prepare_repsonse(self, hostname, prompt, command,
                          failed_when_contains, response_class=Response):

        genie_device_mapper = {
            "cisco_ios": "ios",
            "cisco_xe": "iosxe",
            "cisco_xr": "iosxr",
            "cisco_nxos": "nxos",
            "cisco_asa": "asa",
        }
        genie_device_type = genie_device_mapper[self.device_type]

        response = response_class(
                host=hostname,
                initial_prompt=prompt,
                channel_input=command,
                failed_when_contains=failed_when_contains,
        )

        response.genie_platform = genie_device_type

        return response

    def _enter_config_mode(self, **kwargs):
        self.enable()
        response = self._prepare_repsonse(hostname=self.host,
                                          prompt=self._base_prompt,
                                          failed_when_contains=self.failed_when_contains,
                                          command="configuration terminal",
                                          response_class=ConfigCommandResponse,
                                          )
        self.config_mode(**kwargs)
        prompt = self.find_prompt()

        response = self._prepare_result(response=response,
                                        response_prompt=prompt,
                                        result="")
        return response

    def _exit_config_mode(self, command="end", **kwargs):
        response = self._prepare_repsonse(hostname=self.host,
                                          prompt=self._base_prompt,
                                          failed_when_contains=self.failed_when_contains,
                                          command=command,
                                          response_class=ConfigCommandResponse,
                                          )
        self.exit_config_mode(exit_config=command, **kwargs)

        prompt = self.find_prompt()
        response = self._prepare_result(response=response,
                                        response_prompt=prompt,
                                        result=""
                                        )

        return response

    def _send_command(self, command, structured=False,
                      **kwargs):
        response = self._prepare_repsonse(hostname=self.host,
                                          prompt=self._base_prompt,
                                          command=command,
                                          failed_when_contains=self.failed_when_contains)
        result = self.send_command(command, use_genie=structured,
                                   **kwargs)

        response = self._prepare_result(response=response,
                                        response_prompt=self._base_prompt,
                                        result=result)

        return response

    def _send_config_command(self, command, prompt):
        command = command.strip()

        response = self._prepare_repsonse(hostname=self.host,
                                          prompt=prompt,
                                          command=command,
                                          failed_when_contains=self.failed_when_contains,
                                          response_class=ConfigCommandResponse)

        self.write_channel(self.normalize_cmd(command))

        raw_output = self.read_until_prompt_or_pattern(
                pattern=re.escape(
                        command))

        result = self._parse_output(output=raw_output, command=command,
                                    prompt=prompt)

        new_prompt = ""
        if not result:
            new_prompt = self.find_prompt()

        response = self._prepare_result(response=response,
                                        response_prompt=new_prompt,
                                        result=result,
                                        raw_result=raw_output)
        return response

    def _send_config_commands(self, commands, include_mode_change=True):
        interactive_prompt = None
        results = MultiResponse()

        enter_conf_t_output = self._enter_config_mode()

        if include_mode_change:
            results.append(enter_conf_t_output)

        for command in commands:
            if interactive_prompt:
                prompt = interactive_prompt
            else:
                prompt = self.find_prompt()

            response = self._send_config_command(command=command,
                                                 prompt=prompt)

            result = response.result
            if not response.failed and result:
                interactive_prompt = result

            results.append(response)

        exit_conf_t_output = self._exit_config_mode()

        if include_mode_change:
            results.append(exit_conf_t_output)

        return results

    def send_commands(self, commands: Collection[str],
                      structured: bool = False,
                      ) -> Union[Response, MultiResponse]:

        responses = MultiResponse()
        config_mode = False
        config_commands = []

        for index, command in enumerate(commands):

            # check if the proceeding commands are config commands
            if self._enter_config_mode_command(command):
                config_mode = True
                continue

            # if end of config commands or no more commands, send the config
            # commands
            elif self._exit_config_mode_command(command) or index == len(
                    commands) - 1 and config_mode:
                if index == len(commands) - 1 and not \
                        self._exit_config_mode_command(command):
                    config_commands.append(command)
                result = self._send_config_commands(config_commands)
                config_mode = False
                config_commands = []
                responses += result
                continue
            else:
                # if in config mode, append commands to config commands to
                # run all
                # config commands at once
                if config_mode:
                    config_commands.append(command)
                    continue

                # send non config commands immediately
                result = self._send_command(command, structured=structured, )
                responses.append(result)

        if len(responses) == 1:
            response: Response = responses[0]
            return response

        return responses

    def check_enable_mode(self, check_string="#"):
        """Check if in enable mode. Return boolean."""
        return super().check_enable_mode(check_string=check_string)

    def enable(
            self,
            cmd="enable",
            pattern="ssword",
            enable_pattern=None,
            re_flags=re.IGNORECASE,
    ):
        """Enter enable mode."""
        return super().enable(
                cmd=cmd, pattern=pattern, enable_pattern=enable_pattern,
                re_flags=re_flags
        )

    def exit_enable_mode(self, exit_command="disable"):
        """Exits enable (privileged exec) mode."""
        return super().exit_enable_mode(exit_command=exit_command)

    def check_config_mode(self, check_string=")#", pattern=""):
        """
        Checks if the device is in configuration mode or not.

        Cisco IOS devices abbreviate the prompt at 20 chars in config mode
        """
        return super().check_config_mode(check_string=check_string,
                                         pattern=pattern)

    def config_mode(self, config_command="configure terminal", pattern="",
                    re_flags=0):
        """
        Enter into configuration mode on remote device.

        Cisco IOS devices abbreviate the prompt at 20 chars in config mode
        """
        if not pattern:
            pattern = re.escape(self.base_prompt[:16])
        return super().config_mode(
                config_command=config_command, pattern=pattern,
                re_flags=re_flags
        )

    def exit_config_mode(self, exit_config="end", pattern=r"\#"):
        """Exit from configuration mode."""
        return super().exit_config_mode(exit_config=exit_config,
                                        pattern=pattern)

    def serial_login(
            self,
            pri_prompt_terminator=r"\#\s*$",
            alt_prompt_terminator=r">\s*$",
            username_pattern=r"(?:user:|username|login)",
            pwd_pattern=r"assword",
            delay_factor=1,
            max_loops=20,
    ):
        self.write_channel(self.TELNET_RETURN)
        output = self.read_channel()
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                alt_prompt_terminator, output, flags=re.M
        ):
            return output
        else:
            return self.telnet_login(
                    pri_prompt_terminator,
                    alt_prompt_terminator,
                    username_pattern,
                    pwd_pattern,
                    delay_factor,
                    max_loops,
            )

    def telnet_login(
            self,
            pri_prompt_terminator=r"\#\s*$",
            alt_prompt_terminator=r">\s*$",
            username_pattern=r"(?:user:|username|login|user name)",
            pwd_pattern=r"assword",
            delay_factor=1,
            max_loops=20,
    ):
        """Telnet login. Can be username/password or just password."""
        delay_factor = self.select_delay_factor(delay_factor)

        # FIX: Cleanup in future versions of Netmiko
        if delay_factor < 1:
            if not self._legacy_mode and self.fast_cli:
                delay_factor = 1

        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        outer_loops = 3
        inner_loops = int(max_loops / outer_loops)
        i = 1
        for _ in range(outer_loops):
            while i <= inner_loops:
                try:
                    output = self.read_channel()
                    return_msg += output

                    # Search for username pattern / send username
                    if re.search(username_pattern, output, flags=re.I):
                        # Sometimes username/password must be terminated with "\r" and not "\r\n"
                        self.write_channel(self.username + "\r")
                        time.sleep(1 * delay_factor)
                        output = self.read_channel()
                        return_msg += output

                    # Search for password pattern / send password
                    if re.search(pwd_pattern, output, flags=re.I):
                        # Sometimes username/password must be terminated with "\r" and not "\r\n"
                        self.write_channel(self.password + "\r")
                        time.sleep(0.5 * delay_factor)
                        output = self.read_channel()
                        return_msg += output
                        if re.search(
                                pri_prompt_terminator, output, flags=re.M
                        ) or re.search(alt_prompt_terminator, output,
                                       flags=re.M):
                            return return_msg

                    # Support direct telnet through terminal server
                    if re.search(
                            r"initial configuration dialog\? \[yes/no\]: ",
                            output
                    ):
                        self.write_channel("no" + self.TELNET_RETURN)
                        time.sleep(0.5 * delay_factor)
                        count = 0
                        while count < 15:
                            output = self.read_channel()
                            return_msg += output
                            if re.search(r"ress RETURN to get started",
                                         output):
                                output = ""
                                break
                            time.sleep(2 * delay_factor)
                            count += 1

                    # Check for device with no password configured
                    if re.search(r"assword required, but none set", output):
                        self.remote_conn.close()
                        msg = "Login failed - Password required, but none set: {}".format(
                                self.host
                        )
                        raise NetmikoAuthenticationException(msg)

                    # Check if proper data received
                    if re.search(
                            pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                    i += 1

                except EOFError:
                    self.remote_conn.close()
                    msg = f"Login failed: {self.host}"
                    raise NetmikoAuthenticationException(msg)

            # Try sending an <enter> to restart the login process
            self.write_channel(self.TELNET_RETURN)
            time.sleep(0.5 * delay_factor)
            i = 1

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = f"Login failed: {self.host}"
        raise NetmikoAuthenticationException(msg)

    def cleanup(self, command="exit"):
        """Gracefully exit the SSH session."""
        try:
            # The pattern="" forces use of send_command_timing
            if self.check_config_mode(pattern=""):
                self.exit_config_mode()
        except Exception:
            pass
        # Always try to send final 'exit' (command)
        self._session_log_fin = True
        self.write_channel(command + self.RETURN)

    def _autodetect_fs(self, cmd="dir", pattern=r"Directory of (.*)/"):
        """Autodetect the file system on the remote device. Used by SCP operations."""
        if not self.check_enable_mode():
            raise ValueError(
                    "Must be in enable mode to auto-detect the file-system.")
        output = self.send_command_expect(cmd)
        match = re.search(pattern, output)
        if match:
            file_system = match.group(1)
            # Test file_system
            cmd = f"dir {file_system}"
            output = self.send_command_expect(cmd)
            if "% Invalid" in output or "%Error:" in output:
                raise ValueError(
                        "An error occurred in dynamically determining remote file "
                        "system: {} {}".format(cmd, output)
                )
            else:
                return file_system

        raise ValueError(
                "An error occurred in dynamically determining remote file "
                "system: {} {}".format(cmd, output)
        )

    def save_config(
            self,
            cmd="copy running-config startup-config",
            confirm=False,
            confirm_response="",
    ):
        """Saves Config."""
        self.enable()
        if confirm:
            output = self.send_command_timing(
                    command_string=cmd, strip_prompt=False, strip_command=False
            )
            if confirm_response:
                output += self.send_command_timing(
                        confirm_response, strip_prompt=False,
                        strip_command=False
                )
            else:
                # Send enter by default
                output += self.send_command_timing(
                        self.RETURN, strip_prompt=False, strip_command=False
                )
        else:
            # Some devices are slow so match on trailing-prompt if you can
            output = self.send_command(
                    command_string=cmd, strip_prompt=False, strip_command=False
            )
        return output


class CiscoSSHConnection(CiscoBaseConnection):
    pass


class CiscoFileTransfer(BaseFileTransfer):
    pass
