#!/usr/bin/env python3

# Utility functions/classes

import re
import sys
import time
import string
import random
from datetime import timedelta, datetime

class ThreadWriter(object):

    ''' Custom class to write data to a file accross threads '''

    def __init__(self, file_, out_dir):
        self.out_dir  = out_dir
        self.out_file = open(f"{out_dir}{file_}", 'a')

    def write(self, data):
        ''' Write data to file '''
        self.out_file.write(f"{data}\n")

    def close(self):
        ''' Close the file handle '''
        self.out_file.close()


def banner(args, version):
    ''' Construct a tool banner to display settings '''
    BANNER  = "\n            *** Omnispray ***            \n"
    BANNER += "\n>---------------------------------------<\n"
    # Display version
    space   = ' ' * (15 - len('version'))
    BANNER += f"\n   > version{space}:  {version}"
    # Iterate over provided args
    args_ = vars(args)
    for arg in args_:
        # Validate the arg was defined
        if args_[arg]:
            space   = ' ' * (15 - len(arg))
            BANNER += f"\n   > {arg}{space}:  {str(args_[arg])}"
            # Add data meanings
            if arg == 'count':
                BANNER += " passwords/spray"
            if arg == 'lockout':
                BANNER += " minutes"
            if arg == 'rate':
                BANNER += " threads"
            if arg == 'timeout' or arg == 'pause':
                BANNER += " seconds"
    # Add timestamp for start of spray
    space   = ' ' * (15 - len('start'))
    start_t = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    BANNER += f"\n   > start{space}:  {start_t}"
    BANNER += "\n"
    BANNER += "\n>---------------------------------------<\n"
    return BANNER

def get_chunks_from_list(_list, n):
    ''' Yield chunks of N size of a given list '''
    for i in range(0, len(_list), n):
        yield _list[i:i + n]

def check_last_chunk(sublist, full_list):
    ''' Identify if the current list chunk is the last chunk '''
    if sublist[-1] == full_list[-1]:
        return True
    return False

def get_list_from_file(file_):
    ''' Read in a file and return a cleaned list of lines '''
    with open(file_, 'r') as f:
        _list = [line.strip() for line in f if line.strip() not in [None, ""]]
    return _list

def lockout_reset_wait(lockout):
    ''' Perform a lockout reset timer - prettified '''
    # From: https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/core/utils/time.py
    delay = timedelta(
        hours=0,
        minutes=lockout,
        seconds=0
    )
    sys.stdout.write('\n\n')
    for remaining in range(int(delay.total_seconds()), 0, -1):
        sys.stdout.write(f"\r[*] Next spray in: {timedelta(seconds=remaining - 1)}")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write('\n\n')

def write_data(data, file_):
    ''' Given a file handle, write data line by line '''
    if len(data) > 0:
        if type(data) == dict: data = ['%s:%s' % (k, v) for k, v in data.items()]
        for item in data:
            file_.write(f"{item}\n")

def build_email(user, domain):
    ''' Based on a provided domain, force the email structure of a user '''
    if '@' in user:
        if domain != user.split('@')[-1]:
            user = "%s@%s" % (user.split('@')[0], domain)
    else:
        user = "%s@%s" % (user, domain)
    return user

def check_email(user):
    ''' Validate email address syntax (not the best regexp) '''
    return re.fullmatch('[^@]+@[^@]+\.[^@]+', user)

def gen_space(val):
    ''' Generate a fixed length space based on val passed '''
    return ' ' * (75 - len(val))

def random_string(n):
    ''' Return a random string of length N using all ASCII characters '''
    return ''.join(
        random.choice(string.ascii_letters) for _ in range(n)
    )

def random_float(start=0.250, stop=0.750):
    ''' Return a random float between the start and stop to 3 decimals '''
    return float("{:.3f}".format(random.uniform(start, stop)))
