"""
Module that handles all SSH operations - both ssh and ftp
"""
from io import BytesIO
from paramiko.ssh_exception import AuthenticationException

import time
import logging
import paramiko
import paramiko.ssh_gss


class SSHExecutor:
    """
    SSH executor allows to perform remote commands and upload/download files
    """

    def __init__(self, host, username: str, password: str):
        self.ssh_client = None
        self.ftp_client = None
        self.logger = logging.getLogger()
        self.remote_host = host
        self.username = username
        self.password = password
        self.timeout = 3600
        self.max_retries = 3

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close_connections()
        return False

    def __use_gss_api(self) -> bool:
        """
        Check if it is possible to authenticate to the server
        using GSS-API.
        """
        use_gss_api: bool = False
        try:
            paramiko.ssh_gss.GSSAuth(auth_method="gssapi-with-mic")
            use_gss_api = True
        except ImportError:
            pass

        return use_gss_api

    def setup_ssh(self):
        """
        Initiate SSH connection and save it as self.ssh_client
        """
        current_try = 1
        while current_try <= self.max_retries:
            try:
                self.logger.debug('Will set up ssh, attempt %s of %s' % (current_try, self.max_retries))
                if self.ssh_client:
                    self.close_connections()

                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                use_gss_api = self.__use_gss_api()
                if use_gss_api:
                    self.logger.info("Using Kerberos ticket for authentication")
                    self.ssh_client.connect(
                        self.remote_host,
                        username=self.username,
                        timeout=30,
                        gss_auth=use_gss_api,
                    )
                else:
                    self.ssh_client.connect(
                        self.remote_host,
                        username=self.username,
                        password=self.password,
                        timeout=30,
                    )

                self.logger.debug('Done setting up ssh')
                return
            except AuthenticationException as e:
                if current_try == self.max_retries:
                    self.logger.error(f"Max retries reached opening SSH connection")
                    raise e
                current_try += 1

    def setup_ftp(self):
        """
        Initiate SFTP connection and save it as self.ftp_client
        If needed, SSH connection will be automatically set up
        """
        self.logger.debug('Will set up ftp')
        if self.ftp_client:
            self.close_connections()

        if not self.ssh_client:
            self.setup_ssh()

        self.ftp_client = self.ssh_client.open_sftp()
        self.logger.debug('Done setting up ftp')

    def execute_command(self, command):
        """
        Execute command over SSH
        """
        start_time = time.time()
        if isinstance(command, list):
            command = '; '.join(command)

        self.logger.debug('Executing %s', command)
        retries = 0
        while retries <= self.max_retries:
            if not self.ssh_client:
                self.setup_ssh()

            (_, stdout, stderr) = self.ssh_client.exec_command(command, timeout=self.timeout)
            self.logger.debug('Executed %s. Reading response', command)
            stdout_list = []
            stderr_list = []
            for line in stdout.readlines():
                stdout_list.append(line[0:256])

            for line in stderr.readlines():
                stderr_list.append(line[0:256])

            exit_code = stdout.channel.recv_exit_status()
            stdout = ''.join(stdout_list).strip()
            stderr = ''.join(stderr_list).strip()
            # Retry if AFS error occured
            if '.bashrc: Permission denied' in stderr:
                retries += 1
                self.logger.warning('SSH execution failed, will do a retry number %s', retries)
                self.close_connections()
                time.sleep(3)
            else:
                break

        end_time = time.time()
        # Read output from stdout and stderr streams
        self.logger.info('SSH command exit code %s, executed in %.2fs, command:\n\n%s\n',
                         exit_code,
                         end_time - start_time,
                         command.replace('; ', '\n'))

        if stdout:
            self.logger.debug('STDOUT: %s', stdout)

        if stderr:
            self.logger.error('STDERR: %s', stderr)

        return stdout, stderr, exit_code

    def upload_as_file(self, content, copy_to):
        """
        Upload given string as file
        """
        self.logger.debug('Will upload %s bytes as %s', len(content), copy_to)
        if not self.ftp_client:
            self.setup_ftp()

        try:
            self.ftp_client.putfo(BytesIO(content.encode()), copy_to)
            self.logger.debug('Uploaded string to %s', copy_to)
        except Exception as ex:
            self.logger.error('Error uploading file to %s. %s', copy_to, ex)
            return False

        return True

    def upload_file(self, copy_from, copy_to):
        """
        Upload a file
        """
        self.logger.debug('Will upload file %s to %s', copy_from, copy_to)
        if not self.ftp_client:
            self.setup_ftp()

        try:
            self.ftp_client.put(copy_from, copy_to)
            self.logger.debug('Uploaded file to %s', copy_to)
        except Exception as ex:
            self.logger.error('Error uploading file from %s to %s. %s', copy_from, copy_to, ex)
            return False

        return True

    def download_as_string(self, copy_from):
        """
        Download remote file contents as string
        """
        self.logger.debug('Will download file %s as string', copy_from)
        if not self.ftp_client:
            self.setup_ftp()

        remote_file = None
        try:
            remote_file = self.ftp_client.open(copy_from)
            contents = remote_file.read()
            self.logger.debug('Downloaded %s bytes from %s', len(contents), copy_from)
            return contents.decode('utf-8')
        except Exception as ex:
            self.logger.error('Error downloading file from %s. %s', copy_from, ex)
        finally:
            if remote_file:
                remote_file.close()

        return None

    def download_file(self, copy_from, copy_to):
        """
        Download file from remote host
        """
        self.logger.debug('Will download file %s to %s', copy_from, copy_to)
        if not self.ftp_client:
            self.setup_ftp()

        try:
            self.ftp_client.get(copy_from, copy_to)
            self.logger.debug('Downloaded file to %s', copy_to)
        except Exception as ex:
            self.logger.error('Error downloading file from %s to %s. %s', copy_from, copy_to, ex)
            return False

        return True

    def close_connections(self):
        """
        Close any active connections
        """
        if self.ftp_client:
            self.logger.debug('Closing ftp client')
            self.ftp_client.close()
            self.ftp_client = None
            self.logger.debug('Closed ftp client')

        if self.ssh_client:
            self.logger.debug('Closing ssh client')
            self.ssh_client.close()
            self.ssh_client = None
            self.logger.debug('Closed ssh client')
