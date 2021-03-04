#!/usr/bin/env python3

from datetime import datetime

# Default values that can be leveraged by modules

# Get the current time in YYMMDDHHMM format to append
# to file names to keep each run distinct
F_TIME = datetime.now().strftime("%y%m%d%H%M")

# Log and output files
LOG_FILE   = "raw.log"
ENUM_FILE  = "enum_successful_results.{}.txt".format(F_TIME)
SPRAY_FILE = "spray_successful_results.{}.txt".format(F_TIME)

# Tested files
ENUM_TESTED  = "enum_tested.{}.txt".format(F_TIME)
SPRAY_TESTED = "spray_tested.{}.txt".format(F_TIME)

# Deafult HTTP Headers
HTTP_HEADERS = {
    "DNT": "1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "keep-alive",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1"
}

# Microsoft response code map
# https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
# https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f
# Structure: [Flag, Description]
AADSTS_CODES = {
    "AADSTS50053": ["LOCKED", "Account locked"],
    "AADSTS50055": ["EXPIRED_PASS", "Password expired"],
    "AADSTS50057": ["DISABLED", "User disabled"],
    "AADSTS50126": ["INVALID_CREDS", "Invalid username or password"],
    "AADSTS50059": ["MISSING_TENANT", "Tenant for account doesn't exist"],
    "AADSTS50128": ["INVALID_DOMAIN", "Tenant for account doesn't exist"],
    "AADSTS50034": ["USER_NOT_FOUND", "User does not exist"],
    "AADSTS50079": ["VALID_MFA", "Response indicates MFA (Microsoft)"],
    "AADSTS50076": ["VALID_MFA", "Response indicates MFA (Microsoft)"],
    "AADSTS50158": ["SEC_CHAL", "Response indicates conditional access (MFA: DUO or other)"]
}