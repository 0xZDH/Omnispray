# Omnispray

> Omnispray | Modular Enumeration and Password Spraying Framework -- v0.1.2

Omnispray aims to replace tools such as [o365spray](https://github.com/0xZDH/o365spray) and provide a modular framework to expand enumeration and spraying beyond just a single target/application.

The primary goal is to provide a framework to allow for the easy development and implementation of user enumeration and password spraying techniques for a variety of targets/applications. While there are currently several prebuilt modules included, this tool provides module templates to give users the tools needed to extend the tools usage for non-standard cases. The goal is also to provide a central tool to handle all enumeration and spraying.

## Modules

See [MODULES.md](MODULES.md) for information on custom module development as well as details on included modules (O365, OWA, etc.).

## Usage

| Flag         | Description                                                                                                |
|--------------|------------------------------------------------------------------------------------------------------------|
| -m<br/>--module | Specify the module to run via the modules/ directory.                                                   |
| -d<br/>--domain | Target domain for enumeration/spraying.                                                                 |
| -t<br/>--type   | Module type. If left blank, Omnispray will attempt to autodetect the module type based on the module name. {enum, spray} |
| --url  | Target URL. This is for modules that don't use a standard URL for targeting.                                     |
| -u<br/>--user   | Single username/email to process.                                                                       |
| -us<br/>--users | Multiple users/emails to process. (--users uname1 uname2 uname3 ...)                                    |
| -uf<br/>--userfile  | File containing multiple users/emails to process.                                                   |
| -p<br/>--password   | Single password to process.                                                                         |
| -ps<br/>--passwords | Multiple passwords to process. (--passwords password1 password2 password3 ...)                      |
| -pf<br/>--passwordfile | File containing multiple password to process.                                                    |
| -c<br/>--count   | When password spraying, number of password attempts to run before resetting lockout timer. Default: 1  |
| -l<br/>--lockout | Password spraying lockout policy reset time (in minutes). Default: 15 minutes                          |
| -s<br/>--split   | When enumerating, number of usernames to group by during execution                                     |
| -w<br/>--wait    | If splitting user enumeration via --split, time to wait between group runs (in minutes). Default: 5 minutes |
| --timeout     | Request timeout in seconds. Default: 25                                                                   |
| --proxy       | Proxy to pass traffic through (e.g. http://127.0.0.1:8080).                                               |
| --proxy-url   | URL of proxy to request instead of the module URL. This is to be used with tools such as FireProx.        |
| --proxy-headers  | Custom headers to use when a --proxy-url has been provided (e.g. "X-My-X-Forwarded-For: 127.0.0.1" when using FireProx) |
| --pause       | Sleep (jitter) time before each task is executed in seconds. If set to '-1', a random pause, between 0.250 and 0.750, will occur before each task execution. Default: 0.250 |
| --rate        | Number of concurrent connections during enumeration/spraying. Default: 10                                 |
| --version     | Print the tool version                                                                                    |
| --debug       | Print debug information                                                                                   |

### Examples

O365 user enumeration via the Office module.
```
> python3 omnispray.py --type enum -uf users.txt --module o365_enum_office
```

O365 password spraying via the ActiveSync module.
```
> python3 omnispray.py --type spray -uf users.txt -pf passwords.txt \
                       --module o365_spray_activesync \
                       --count 3 --lockout 30
```
