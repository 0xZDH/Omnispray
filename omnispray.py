#!/usr/bin/env python3

# Based on: https://github.com/0xZDH/asyncio-template

import os
import sys
import time
import signal
import logging
import asyncio
import argparse
from pathlib import Path

from core.utils import *

__title__   = "Omnispray | Modular Enumeration and Password Spraying Framework"
__version__ = "0.1"

def signal_handler(signal, frame):
    ''' Signal handler for async routines.
        Call the module's shutdown function to cleanly exit upon
        receiving a CTRL-C signal.
    '''
    module.shutdown(key=True)
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{__title__} -- v{__version__}"
    )

    # Define mutally exclusive groups to handler user(s) and password(s)
    user_group = parser.add_mutually_exclusive_group()
    pass_group = parser.add_mutually_exclusive_group()

    # Target module to run
    parser.add_argument(
        "-m",
        "--module",
        type=str,
        help="Specify the module to run via the modules/ directory."
    )

    # Target domain (if specified, use for email validations)
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        help="Target domain for enumeration/spraying."
    )

    # Module type
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        choices=['enum', 'spray'],
        help="Module type. If left blank, Omnispray will attempt to autodetect " +
             "the module type based on the module name."
    )

    # Target URL for modules that don't use a standard URL
    parser.add_argument(
        "--url",
        type=str,
        help="Target URL."
    )

    # Handle user/users/user file
    user_group.add_argument(
        "-u",
        "--user",
        type=str,
        help="Single username/email to process."
    )
    user_group.add_argument(
        "-us",
        "--users",
        type=str,
        nargs='+',
        help="Multiple users/emails to process."
    )
    user_group.add_argument(
        "-uf",
        "--userfile",
        type=str,
        help="File containing multiple users/emails to process."
    )

    # Handle password/passwords/password file
    pass_group.add_argument(
        "-p",
        "--password",
        type=str,
        help="Single password to process."
    )
    pass_group.add_argument(
        "-ps",
        "--passwords",
        type=str,
        nargs='+',
        help="Multiple passwords to process."
    )
    pass_group.add_argument(
        "-pf",
        "--passwordfile",
        type=str,
        help="File containing multiple passwords to process."
    )

    # Password spraying lockout policy handling
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help="Number of password attempts to run before resetting " +
             "lockout timer. Default: 1"
    )
    parser.add_argument(
        "-l",
        "--lockout",
        type=float,
        help="Lockout policy reset time (in minutes). Default: 15 minutes",
        default=15.0
    )

    # HTTP request handlers
    parser.add_argument(
        "--timeout",
        type=int,
        default=25,
        help="Request timeout in seconds. Default: 25"
    )
    parser.add_argument(
        "--proxy",
        type=str,
        help="Proxy to pass traffic through (e.g. http://127.0.0.1:8080)."
    )

    # Generic tool flags
    parser.add_argument(
        "--rate",
        type=int,
        default=10,
        help="Number of concurrent connections during enumeration/spraying. " +
             "Default: 10"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the tool version."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug output"
    )

    args = parser.parse_args()

    # Print the tool version and exit
    if args.version:
        print(f"{__title__} v{__version__}")
        sys.exit(0)

    # Track execution time
    exec_start = time.time()

    # Initialize logging level and format
    if args.debug:
        logging_format = "[%(asctime)s] %(levelname)-5s - %(filename)20s:%(lineno)-4s " + \
                         "- %(message)s"
        logging_level  = logging.DEBUG
    else:
        logging_format = "[%(asctime)s] %(levelname)-5s: %(message)s"
        logging_level  = logging.INFO

    logging.basicConfig(format=logging_format, level=logging_level)
    logging.addLevelName(logging.WARNING, "WARN")

    # - Handle flag validations

    if not args.module:
        logging.error("Missing arguments: -m/--module")
        sys.exit(1)

    # Require a user, list of users, or file of users
    if (not args.user and not args.users and not args.userfile):
        logging.error("Missing arguments: -u/--user | -us/--users | -uf/--userfile")
        sys.exit(1)

    # Ensure that a file(s) passed in are valid file(s)
    if (args.userfile and not os.path.isfile(args.userfile)):
        logging.error(f"Invalid file: {args.userfile}")
        sys.exit(1)

    if (args.passwordfile and not os.path.isfile(args.passwordfile)):
        logging.error(f"Invalid file: {args.passwordfile}")
        sys.exit(1)

    # - Begin module validation

    # Validate the module provided by the user is, in fact, a module within
    # the modules directory

    # First, store a backup of the original value provided by the user
    orig_mod = args.module

    # If no type is provided, check if the module is in a valid 'type'
    # directory by checking for enum/ or spray/ in the value passed by
    # the user
    if not args.type:
        if any(f"{p}/" in args.module for p in ['enum', 'spray']):
            args.type  = args.module.split('/')[-2]

    # Then, strip any directories provided with the value
    args.module = args.module.split('/')[-1]

    # If the extension is included, strip
    if args.module[-3:] == '.py':
        args.module = args.module[:-3]

    # Now, validate the module file exists within the modules/ dir
    if args.type:
        valid_module = os.path.isfile(f"modules/{args.type}/{args.module}.py")

    # Attempt to dynamically identify the module type
    else:
        for t in ['enum', 'spray']:
            valid_module = os.path.isfile(f"modules/{t}/{args.module}.py")
            if valid_module:
                args.type = t
                break

    if not valid_module:
        logging.error(f"Invalid module file: {orig_mod}")
        logging.error("Please ensure the module Python file exists within the "
                      "modules/ directory in the correct module type subdirectory.")
        sys.exit(1)

    # If the module exists, attempt to import
    try:
        module_import = __import__(f"modules.{args.type}.{args.module}", fromlist=['ASModule'])
    except ModuleNotFoundError:
        logging.error(f"Module, modules.{args.type}.{args.module}, failed to import 'ASModule'.")
        sys.exit(1)

    # - Begin building the framework

    print(banner(args, __version__))

    # Initialize the Asyncio loop
    loop = asyncio.get_event_loop()

    # Add signal handler to handle ctrl-c interrupts
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    CUR_DIR = Path(__file__).parent.absolute()
    LOG_DIR = f"{CUR_DIR}/logs/"
    OUT_DIR = f"{CUR_DIR}/results/"

    # Create log/output directories (if not already present)
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    # Build the module parameters and initialize the module class
    kwargs = { 'loop': loop, 'args': args, 'log_dir': LOG_DIR,
               'out_dir': OUT_DIR }
    module = module_import.ASModule(**kwargs)

    # If the module has prechecks, run them and exit if any
    # prechecks fail
    module_precheck = getattr(module, "prechecks", None)
    if callable(module_precheck):
        if not module_precheck():
            sys.exit(1)

    # Since all modules will require at least a set of user(s),
    # perform item transformations to a uniform data type: List
    # Single user to be processed
    if args.user:
        users = [args.user]

    # List of/multiple users to be processed
    elif args.users:
        users = args.users

    # File of users to be processed
    else:
        users = get_list_from_file(args.userfile)

    # - Begin enumeration/spraying

    try:

        # Handle user enumeration module
        if module.type == "enum":

            logging.info(f"Enumerating {len(users)} users via '{args.module}' module")

            # Provide the option to allow passing a custom password to the enumeration
            # module if needed
            if args.password:
                password = args.password
            else:
                password = 'password'

            # Run the loop
            loop.run_until_complete(module.run(users, password))

        # Handle password spray module
        elif module.type == "spray":

            # Require a password, list of passwords, or file of passwords
            if (not args.password and not args.passwords and not args.passwordfile):
                logging.error("Missing arguments: -p/--password | -ps/--passwords | "
                              "-pf/--passwordfile")
                sys.exit(1)

            logging.info(f"Password spraying {len(users)} users via '{args.module}' module")

            # Perform item transformations to a uniform data type: List
            # Single password to be processed
            if args.password:
                passwords = [args.password]

            # List of/multiple passwords to be processed
            elif args.passwords:
                passwords = args.passwords

            # File of passwords to be processed
            else:
                passwords = get_list_from_file(args.passwordfile)

            # Set the user list for the module class
            module.users = users

            # Based on: https://github.com/0xZDH/o365spray
            for password_chunk in get_chunks_from_list(passwords, args.count):
                logging.info("Password spraying the following passwords: [%s]" % (
                    ", ".join("'%s'" % password for password in password_chunk))
                )

                # Loop through each password individually so it's easier to keep
                # track and avoid duplicate scans once a removal condition is hit
                for password in password_chunk:
                    loop.run_until_complete(module.run(password))

                    # If the module has a defined lockout handler, stop if we hit
                    # the threshold
                    if hasattr(module, 'locked_count'):
                        if module.locked_count >= module.lockout_limit:
                            logging.error("Lockout threashold reached. Exiting...")
                            break

                # https://stackoverflow.com/a/654002
                # https://docs.python.org/3/tutorial/controlflow.html#break-and-continue-statements-and-else-clauses-on-loops
                # Only executed if the inner loop did NOT break
                else:
                    # Check if we reached the last password chunk
                    if not check_last_chunk(password_chunk, passwords):
                        lockout_reset_wait(args.lockout)
                    continue

                # Only executed if the inner loop DID break
                break

            else:
                logging.error(f"Invalid module type: {module.type}")

        # Call the module's shutdown function to exit cleanly. Otherwise,
        # it can be triggered via a CTRL-C signal.
        module.shutdown()

        loop.run_until_complete(asyncio.sleep(0.250))
        loop.close()

    except KeyboardInterrupt as e:
        pass

    # Display tracked timer
    print()  # Add a new line before final output
    elapsed = time.time() - exec_start
    logging.info(f"{__file__} executed in {elapsed:.2f} seconds.")
