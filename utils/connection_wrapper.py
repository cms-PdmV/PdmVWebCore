"""
Module that contains ConnectionWrapper class
"""
import http.client
import logging
import os
import json
import time


class ConnectionWrapper():
    """
    HTTP client wrapper class to re-use existing connection
    """

    def __init__(self, host, port=443, https=True, timeout=120, keep_open=False, max_attempts=3):
        self.logger = logging.getLogger('logger')
        self.connection = None
        self.connection_attempts = max_attempts
        self.host_url = host.replace('https://', '').replace('http://', '')
        self.cert_file = os.getenv('USERCRT', None)
        self.key_file = os.getenv('USERKEY', None)
        self.timeout = timeout
        self.keep_open = keep_open
        self.port = port
        self.https = https

    def init_connection(self, url):
        """
        Return a new HTTPSConnection
        """
        if self.cert_file is None or self.key_file is None:
            self.cert_file = os.getenv('USERCRT', None)
            self.key_file = os.getenv('USERKEY', None)

        if self.cert_file is None or self.key_file is None:
            raise Exception('Missing USERCRT or USERKEY environment variables')

        if self.https:
            return http.client.HTTPSConnection(url,
                                               port=self.port,
                                               cert_file=self.cert_file,
                                               key_file=self.key_file,
                                               timeout=self.timeout)

        return http.client.HTTPConnection(url,
                                          port=self.port,
                                          timeout=self.timeout)

    def __refresh_connection(self, url):
        """
        Recreate a connection
        """
        self.logger.debug('Refreshing connection')
        self.connection = self.init_connection(url)

    def close(self):
        """
        Close connection if it exists
        """
        if self.connection:
            self.logger.debug('Closing connection for %s', self.host_url)
            self.connection.close()
            self.connection = None

    def api(self, method, url, data=None, headers=None):
        """
        Make a HTTP request to given url
        """
        if not self.connection:
            self.__refresh_connection(self.host_url)

        all_headers = {"Accept": "application/json"}
        if headers:
            all_headers.update(headers)

        url = url.replace('#', '%23')
        # this way saves time for creating connection per every request
        for i in range(self.connection_attempts):
            if i != 0:
                self.logger.debug('Connection attempt number %s', i + 1)

            start_time = time.time()
            try:
                self.connection.request(method,
                                        url,
                                        json.dumps(data) if data else None,
                                        headers=all_headers)
                response = self.connection.getresponse()
                if response.status != 200:
                    self.logger.error('Error %d while doing a %s to %s: %s',
                                      response.status,
                                      method,
                                      url,
                                      response.read())
                    return None

                response_to_return = response.read()
                if not self.keep_open:
                    self.close()

                end_time = time.time()
                self.logger.debug('%s request to %s%s took %.2f',
                                  method,
                                  self.host_url,
                                  url,
                                  end_time - start_time)
                return response_to_return
            # except http.client.BadStatusLine:
            #     raise RuntimeError('Something is really wrong')
            except Exception as ex:
                self.logger.error('Exception while doing a %s to %s: %s',
                                  method,
                                  url,
                                  str(ex))
                # most likely connection terminated
                self.__refresh_connection(self.host_url)

        self.logger.error('Connection wrapper failed after %d attempts',
                          self.connection_attempts)
        return None
