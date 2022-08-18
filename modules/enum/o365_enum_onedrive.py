#!/usr/bin/env python3

import sys
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

class OmniModule(object):

    # Counter for successful results of each task
    successful_results = 0

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
        # Open file handles for writing test/success cases
        self.tested_file  = ThreadWriter(ENUM_TESTED, self.out_dir)
        self.success_file = ThreadWriter(ENUM_FILE, self.out_dir)

    def shutdown(self, key=False):
        ''' Perform a shutdown and clean up of the asynchronous handler '''
        print()  # Print empty line
        if key:
            logging.warning("CTRL-C caught...")
        logging.info(f"Results can be found in: '{self.out_dir}'")

        # https://stackoverflow.com/a/48351410
        # https://gist.github.com/yeraydiazdiaz/b8c059c6dcfaf3255c65806de39175a7
        # Unregister _python_exit while using asyncio
        # Shutdown ThreadPoolExecutor and do not wait for current work
        import atexit
        atexit.unregister(concurrent.futures.thread._python_exit)
        self.executor.shutdown = lambda wait:None

        # Let the user know the number of valid users identified
        logging.info(f"Valid user accounts: {self.successful_results}")

        # Close the open file handles
        self.tested_file.close()
        self.success_file.close()

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

    def prechecks(self):
        ''' Perform module prechecks to validate certain data is set
            via command line args. '''
        if not self.args.domain:
            logging.error("Missing module arguments: -d/--domain")
            return False

        return True

    def _execute(self, user, password):
        ''' Perform an asynchronous task '''
        try:
            # Task jitter
            self.args.pause()

            # --------------------------------------------------------
            # For new modules, modify the below code block logic

            # Via: https://github.com/0xZDH/o365spray/blob/master/core/handlers/enumerator.py#L151
            ''' Enumerate users on Microsoft using One Drive
                https://github.com/nyxgeek/onedrive_user_enum/blob/master/onedrive_enum.py
                https://www.trustedsec.com/blog/achieving-passive-user-enumeration-with-onedrive/ '''

            # Write the tested user in its original format
            self.tested_file.write(f"{user}")

            # Remove email format from user if present
            user = user.split('@')[0]

            # Collect the pieces to build the One Drive URL
            domain_array = (self.args.domain.split('.'))
            tenant_array = (self.args.tenant.split('.')) if self.args.tenant else []

            domain = domain_array[0]        # Collect the domain
            tenant = tenant_array[0] if tenant_array else domain  # if tenant param exists use it instead of domain
            tld    = domain_array[-1]       # Grab the TLD
            user   = user.replace(".","_")  # Replace any `.` with `_` for use in the URL

            url    = "https://{TENANT}-my.sharepoint.com/personal/{USERNAME}_{DOMAIN}_{TLD}/_layouts/15/onedrive.aspx".format(
                TENANT=tenant, USERNAME=user, DOMAIN=domain, TLD=tld
            )

            response = self._send_request(requests.get,
                                          url)
            r_status = response.status_code

            # It appears that valid browser User-Agents will return a 302 redirect
            # instead of 401/403 on valid accounts
            if r_status in [302, 401, 403]:
                self.successful_results += 1
                self.success_file.write(f"{user}")
                logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {user}")

            elif r_status == 404:
                print(f"{text_colors.red}[ - ]{text_colors.reset} {user}{gen_space(user)}", end='\r')

            else:
                print(f"{text_colors.yellow}[ - ]{text_colors.reset} {user}{gen_space(user)}", end='\r')

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
