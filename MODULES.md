# Modules

## Custom Modules

To develop a custom module, see the following template files:
* [Enumeration Template](modules/__enum_template__.py)
* [Spraying Template](modules/__spray_template__.py)

These templates are meant to allow a user to easily develop custom modules by following the `TODO` comments within the `_execute` function. The prebuilt modules can also be referenced for how to handle different success/fail scenarios.

Omnispray handles the asynchronous execution and username/password pass through to the module. When designing and developing a custom module, the user only needs to implement the HTTP request/response process and success/fail scenario handling.


## Prebuilt Modules

### Enumeration

> Microsoft Office 365: The default module used by o365spray.py is `o365_enum_office`

| Name | Target | Source(s) | Technique |
| ---  | ---    | ---       | ---       |
| o365_enum_activesync | Office 365 | o365spray<br/>[grimhacker: office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/) | Confirm the HTTP response status code when requesting https://outlook.office365.com/Microsoft-Server-ActiveSync with a username/email and a password (defaults to 'password') via BasicAuth. |
| o365_enum_office     | Office 365 | o365spray<br/>[gremwell: o365enum](https://github.com/gremwell/o365enum) | Confirm the value of `IfExistsResult` in the response body when requesting https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US with a username/email via `username` in the JSON POST data. |
| o365_enum_onedrive   | Office 365 | o365spray<br/>[nyxgeek: onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) | Confirm the HTTP response status code when requesting https://[TENANT]-my.sharepoint.com/personal/[USER]\_[DOMAIN]\_[TLD]/_layouts/15/onedrive.aspx and filling in the specific information within the URL via the username/email and target domain (via --domain). |

### Password Spraying

> Microsoft Office 365: The default module used by o365spray.py is `o365_spray_activesync`

| Name | Target | Source(s) | Technique |
| ---  | ---    | ---       | ---       |
| o365_spray_activesync | Office 365 | o365spray<br/>[grimhacker: office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/) | Confirm the HTTP response status code when requesting https://outlook.office365.com/Microsoft-Server-ActiveSync with a username/email and a password via BasicAuth. |
| o365_spray_adfs       | Office 365 | o365spray<br/>[Mr-Un1k0d3r: adfs-spray](https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py) | Confirm the HTTP response status code when requesting the target's specified ADFS URL (via --url) with a username/email and a password via `UserName=[USER]&Password=[PASSWORD]&AuthMethod=FormsAuthentication` POST data. |
| o365_spray_msol       | Office 365 | o365spray<br/>[dafthack: MSOLSpray](https://github.com/dafthack/MSOLSpray)<br/>[byt3bl33d3r Gist](https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f) | Confirm the HTTP response status code when requesting https://login.microsoft.com/common/oauth2/token with a username/email and a password via the `username` and `password` parameters in the JSON POST data. This method performs a prerequisite request to gather session data. |
