#!/usr/bin/env python3

# -- Password Spray Module Template -- #

# TODO: Add any dependency imports required for new modules.

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
        # Open file handles for logging and writing test/success cases
        self.log_file     = ThreadWriter(LOG_FILE, kwargs['log_dir'])
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
        self.log_file.close()
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

    def prechecks(self):
        ''' Perform module prechecks to validate certain data is set
            via command line args.

        TODO: Modify or remove this function as needed. Retruning False
              will cause Omnispray to exit, returning True will allow the
              module to run as expected.
        '''
        # Validate the user provided a domain when required
        if not self.args.domain:
            logging.error("Missing module arguments: -d/--domain")
            return False

        # Validate the user provided a URL when required
        if not self.args.url:
            logging.error("Missing module arguments: --url")
            return False

        return True

    def _execute(self, user, password):
        ''' Perform an asynchronous task '''
        try:
            # Task jitter
            self.args.pause()

            # --------------------------------------------------------
            # For new modules, modify the below code block logic

            # TODO: This is the 'core' function of the module that will handle the
            #       logic for the spray task being performed.

            # Write the tested user in its original format with the password
            # via: user:password
            self.tested_file.write(f"{user}:{password}")

            # TODO: If the domain is required for setting users via DOMAIN\user or
            #       any other reason, validate the domain was provided via the
            #       `prechecks` function.
            # TODO: If email addresses are required, validate with domain
            #       or validate the user provided is in an email format.
            # Perform email check and validation
            if self.args.domain:
                user = build_email(user, self.args.domain)

            elif not check_email(user):
                logging.error(f"Invalid user: {user}")
                return

            # TODO: Set the final target URL here and define any params like email
            #       or password via: {EMAIL} / {PASSWORD} within the string defitiniton
            #       If the target URL has GET parameters like user/password -
            #       set via .format().
            url = "https://localhost"

            # TODO: If the URL is custom per target, the --url flag can be leveraged,
            #       but ensure to validate the URL was provided via the `prechecks`
            #       function.
            url = self.args.url

            # TODO: If the --proxy-url flag is specified, use that instead of the
            #       specified URL to pass all traffic through.
            if self.args.proxy_url:
                url = self.args.proxy_url

            # TODO: Define a custom set of headers if the request requires specific
            #       data to be passed via request headers, or set/add headers to the
            #       default HTTP headers.
            #       Delete this and the `headers` param set in the _send_request if
            #       not using.
            custom_headers = { 'User-Agent': "...",
                               'Connection': "keep-alive" }
            # ----
            custom_headers = HTTP_HEADERS
            custom_headers['Custom-Header'] = "Value"

            # TODO: If the --proxy-url flag is specified, and the user provided custom
            #       headers via --proxy-headers, set them via the custom_headers
            if self.args.proxy_url and self.args.proxy_headers:
                for header in self.args.proxy_headers:
                    header = header.split(':')
                    custom_headers[header[0]] = ':'.join(header[1:]).strip()

            # TODO: Build POST data, if applicable, based on direct or JSON objects.
            #       Choose one or the other of the following objects and set them
            #       in the _send_request call accordingly.
            #       Delete these and their corresponding params in _send_request if
            #       not using.
            data  = f"password={password}"
            # ----
            jData = f"{{ 'password': {password} }}"

            # TODO: If BasicAuth is required, establish a BasicAuth object and pass
            #       to the _send_request function.
            #       Delete this and the `auth` param in _send_request if not using.
            auth  = HTTPBasicAuth(user, password)

            # TODO: Perform an HTTP request and collect the results. Pass the HTTP
            #       request type via the first parameter and any subsequent data
            #       required after (url, data, headers, etc.).
            req_type    = requests.post  # requests.get
            response    = self._send_request(req_type,
                                             url,
                                             auth=auth,
                                             data=data,
                                             json=jData,
                                             headers=custom_headers)

            # Write the raw data we are parsing to the logs
            self.log_file.write(response.content)


            # TODO: Perform response analysis below to identify valid/invalid cases.


            # TODO: Perform analysis on the response code. Use r_status if the
            #       mechanism for a identifying valid vs. failed use-cases is based
            #       on the response HTTP code.
            #       Delete this if not using.
            r_status = response.status_code
            if r_status == 200:
                self.successful_results += 1
                self.success_file.write(f"{user}:{password}")
                self.users.remove(user)  # Stop spraying user if valid
                logging.info("VALID")
            else:
                logging.info("INVALID")


            # TODO: Perform analysis on the response headers. Use r_headers if the
            #       mechanism for a identifying valid vs. failed use-cases is based
            #       on the response headers.
            r_headers = response.headers
            if "target_header" in (h.lower() for h in r_headers.keys()):
                self.successful_results += 1
                self.success_file.write(f"{user}:{password}")
                self.users.remove(user)  # Stop spraying user if valid
                logging.info("VALID")
            else:
                logging.info("INVALID")


            # TODO: Perform analysis on the response body. Use r_body if the
            #       mechanism for a identifying valid vs. failed use-cases is based
            #       on the response body.
            r_body = response.content
            if "target_value" in r_body:
                self.successful_results += 1
                self.success_file.write(f"{user}:{password}")
                self.users.remove(user)  # Stop spraying user if valid
                logging.info("VALID")
            else:
                logging.info("INVALID")

            # TODO: Perform any custom post analysis handling here.

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


    # TODO: If any custom/pre requests need to be made, custom functions can be
    #       placed below and called to retrieve specific data required for the
    #       final request.
