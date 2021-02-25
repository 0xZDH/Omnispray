# Omnispray

Modular Enumeration and Password Spraying Suite.

This tool aims to replace tools such as o365spray and provide a modular framework to expand enumeration and spraying beyond just a single target. Enumeration and spraying module templates are included in the modules/ directory and can be used to build out custom modules.

## Usage

> Omnispray | Modular Enumeration and Password Spraying Suite -- v0.1

| Flag         | Description                                                                                                  |
|--------------|--------------------------------------------------------------------------------------------------------------|
| -m, --module | Specify the module to run via the modules/ directory.                                                        |
| -d, --domain | Target domain for enumeration/spraying.                                                                      |
| -t, --type   | Module type. If left blank, Omnispray will attempt to autodetect the module type based on the module name. {enum, spray} |
| --url        | Target URL. This is for modules that don't use a standard URL for targeting.                                 |
| -u, --user   | Single username/email to process.                                                                            |
| -us, --users | Multiple users/emails to process. (--users uname1 uname2 uname3 ...)                                         |
| -uf, --userfile  | File containing multiple users/emails to process.                                                        |
| -p, --password   | Single password to process.                                                                              |
| -ps, --passwords | Multiple passwords to process. (--users uname1 uname2 uname3 ...)                                        |
| -pf, --passwordfile | File containing multiple password to process.                                                         |
| -c, --count   | Number of password attempts to run before resetting lockout timer. Default: 1                               |
| -l, --lockout | Lockout policy reset time (in minutes). Default: 15 minutes                                                 |
| --timeout     | Request timeout in seconds. Default: 25                                                                     |
| --proxy       | Proxy to pass traffic through (e.g. http://127.0.0.1:8080).                                                 |
| --rate        | Number of concurrent connections during verification. Default: 10                                           |
| --version     | Print the tool version                                                                                      |
| --debug       | Print debug information                                                                                     |

## Pre-built Modules

Currently, the included modules are ported from [o365spray](https://github.com/0xZDH/o365spray) for Microsoft O365 enumeration and password spraying. Default modules in o365spray:
* Enumeration: Office -> modules/enum/o365_enum_office.py
* Spraying: Activesync -> modules/spray/o365_spray_activesync.py

## Custom Modules

To write a custom module, see the following files:
* [Enumeration Template](modules/__enum_template__.py)
* [Spraying Template](modules/__spray_template__.py)

The framework already handles the username and password pass through along with the asynchronous processing. Within each template is a section under the `_execute` function where the core logic should be placed. Follow the instructions/notes provided via the TODO comments and reference the pre-built modules for examples.