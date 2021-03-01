# Custom Modules

To develop a custom module, see the following template files:
* [Enumeration Template](modules/__enum_template__.py)
* [Spraying Template](modules/__spray_template__.py)

These templates are meant to allow a user to easily develop custom modules by following the `TODO` comments within the `_execute` function. The prebuilt modules can also be referenced for how to handle different success/fail scenarios.

Omnispray handles the asynchronous execution and username/password pass through to the module. When designing and developing a custom module, the user only needs to implement the HTTP request/response process and success/fail scenario handling.

> When writing, testing and adding a new module, add the final Python module file to the [modules/](modules/) directory and in the corresponding module type subdirectory ([modules/enum/](modules/enum/) | [modules/spray/](modules/spray/)).

---

# Prebuilt Modules

All modules can be found in the [modules/](modules/) directory. They are broken up into two subdirectories: enum and spray.

> The `Reference(s)` columns in the below tables are used to identify the original tool and/or research the module is based on. This does not indicate endorsement or acknowledgement of any kind from the original authors.

## Enumeration

> Office 365: The default module used by o365spray.py is `o365_enum_office`

<table>
  <tr>
    <th>Name</th> <th>Target</th> <th>Reference(s)</th> <th>Technique</th>
  </tr>

  <!-- O365 Enumeration via ActiveSync module -->
  <tr>
    <td> o365_enum_activesync </td>
    <td> O365 </td>
    <td><a href="https://bitbucket.org/grimhacker/office365userenum/src/master/">grimhacker: office365userenum</a> </td>
    <td> Confirm the HTTP response status code when requesting <a href="#">https://outlook.office365.com/Microsoft-Server-ActiveSync</a> with a username/email and a password (defaults to 'password') via BasicAuth.<br/><br/>* <b>This performs a single authentication attempt per user</b> </td>
  </tr>

  <!-- O365 Enumeration via Office.com module -->
  <tr>
    <td> o365_enum_office </td>
    <td> O365 </td>
    <td><a href="https://github.com/gremwell/o365enum">gremwell: o365enum</a> </td>
    <td> Confirm the value of 'IfExistsResult' in the response body when requesting <a href="#">https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US</a> with a username/email via 'username' in the JSON POST data. </td>
  </tr>

  <!-- O365 Enumeration via OneDrive module -->
  <tr>
    <td> o365_enum_onedrive </td>
    <td> O365 </td>
    <td><a href="https://github.com/nyxgeek/onedrive_user_enum">nyxgeek: onedrive_user_enum</a> </td>
    <td> Confirm the HTTP response status code when requesting<br/><a href="#">https://[TENANT]-my.sharepoint.com/personal/<br/>[USER]_[DOMAIN]_[TLD]/_layouts/15/onedrive.aspx</a> and filling in the specific information within the URL via the username/email and target domain (via --domain). </td>
  </tr>

  <!-- OWA Enumeration via ActiveSync timing module -->
  <tr>
    <td> owa_enum_activesync </td>
    <td> OWA </td>
    <td> <a href="https://github.com/fugawi/EASSniper">fugawi: EASSniper</a> </td>
    <td> Identify a baseline response time for invalid users. Compare for faster HTTP response times when requesting <a href="#">https://[domain]/Microsoft-Server-ActiveSync</a> with a username (DOMAIN\username) and a password (defaults to 'password') via BasicAuth.<br/><br/>* <b>This performs a single authentication attempt per user</b> </td>
  </tr>
</table>


## Password Spraying

> Office 365: The default module used by o365spray.py is `o365_spray_activesync`

<table>
  <tr>
    <th>Name</th> <th>Target</th> <th>Reference(s)</th> <th>Technique</th>
  </tr>

  <!-- O365 Spraying via ActiveSync module -->
  <tr>
    <td> o365_spray_activesync </td>
    <td> O365 </td>
    <td><a href="https://bitbucket.org/grimhacker/office365userenum/src/master/">grimhacker: office365userenum</a> </td>
    <td> Confirm the HTTP response status code when requesting <a href="#">https://outlook.office365.com/Microsoft-Server-ActiveSync</a> with a username/email and a password via BasicAuth. </td>
  </tr>

  <!-- O365 Spraying via ADFS module -->
  <tr>
    <td> o365_spray_adfs </td>
    <td> O365 </td>
    <td><a href="https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py">Mr-Un1k0d3r: adfs-spray</a> </td>
    <td> Confirm the HTTP response status code when requesting the target's specified ADFS URL (via --url) with a username/email and a password via 'UserName=[USER]&Password=[PASSWORD]&AuthMethod=FormsAuthentication' POST data. </td>
  </tr>

  <!-- O365 Spraying via MSOL module -->
  <tr>
    <td> o365_spray_msol </td>
    <td> O365 </td>
    <td>
        <a href="https://github.com/dafthack/MSOLSpray">dafthack: MSOLSpray</a><br/>
        <a href="https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f">byt3bl33d3r Gist</a><br/>
    </td>
    <td> Confirm the HTTP response status code when requesting <a href="#">https://login.microsoft.com/common/oauth2/token</a> with a username/email and a password via the 'username' and 'password' parameters in the JSON POST data. This method performs a prerequisite request to gather session data. </td>
  </tr>

  <!-- OWA Spraying via ActiveSync module -->
  <tr>
    <td> owa_spray_activesync </td>
    <td> OWA </td>
    <td> <a href="https://github.com/fugawi/EASSniper">fugawi: EASSniper</a> </td>
    <td> Confirm the HTTP response status code when requesting <a href="#">https://[domain]/Microsoft-Server-ActiveSync</a> with a username (DOMAIN\username) and a password via BasicAuth. Currently, any non-401 HTTP response code will show as a valid credential. </td>
  </tr>
</table>