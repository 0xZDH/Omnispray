### Table of Contents

* [**Custom Modules**](#custom-modules)
* [**Prebuilt Modules**](#prebuilt-modules)
  * [Enumeration](#enumeration)
    * [Office 365](#microsoft-office-365)
    * [OWA](#owa)
  * [Password Spraying](#password-spraying)
    * [Office 365](#microsoft-office-365-1)
    * [OWA](#owa-1)

---

# Custom Modules

To develop a custom module, see the following template files:
* [Enumeration Template](modules/__enum_template__.py)
* [Spraying Template](modules/__spray_template__.py)

These templates are meant to allow a user to easily develop custom modules by following the `TODO` comments within the `_execute` function. The prebuilt modules can also be referenced for how to handle different success/fail scenarios.

Omnispray handles the asynchronous execution and username/password pass through to the module. When designing and developing a custom module, the user only needs to implement the HTTP request/response process and success/fail scenario handling.

> When writing, testing and adding a new module, add the final Python module file to the [modules/](modules/) directory and in the corresponding module type subdirectory ([modules/enum/](modules/enum/) | [modules/spray/](modules/spray/)).

---

# Prebuilt Modules

All modules can be found in the [modules/](modules/) directory. They are broken up into two subdirectories: [enum](modules/enum/) and [spray](modules/spray/).

> The `Reference(s)` rows in the below tables are used to identify the original tool and/or research the module is based on. This does not indicate endorsement or acknowledgement of any kind from the original authors.

## Enumeration

### Microsoft Office 365

> O365 User Enumeration: The default module used by o365spray.py is `o365_enum_office`

<!-- O365 Enumeration via ActiveSync module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/enum/o365_enum_activesync.py">o365_enum_activesync</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> Microsoft Office 365 / O365 </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td> <a href="https://bitbucket.org/grimhacker/office365userenum/src/master/">grimhacker: office365userenum</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the HTTP response status code is '200' when requesting <a href="#">https://outlook.office365.com/Microsoft-Server-ActiveSync</a> with a username/email and a password (defaults to 'password') via BasicAuth.<br/><br/>
      * <b>This performs a single authentication attempt per user</b>
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td> - </td>
  </tr>
</table>

<br />

<!-- O365 Enumeration via Office.com module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/enum/o365_enum_office.py">o365_enum_office</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> Microsoft Office 365 / O365 </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td><a href="https://github.com/gremwell/o365enum">gremwell: o365enum</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the value of 'IfExistsResult' is '0' or '6' in the response body when requesting <a href="#">https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US</a> with a username/email via 'username' in the JSON POST data. The value '5' also indicates a valid user, but for a different Identity Provider.<br />
      This method performs two generic prerequisite requests to gather session data.
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td> - </td>
  </tr>
</table>

<br />

<!-- O365 Enumeration via OneDrive module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/enum/o365_enum_onedrive.py">o365_enum_onedrive</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> Microsoft Office 365 / O365 </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td><a href="https://github.com/nyxgeek/onedrive_user_enum">nyxgeek: onedrive_user_enum</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the HTTP response status code is '302', '401', or '403' when requesting <a href="#">https://[TENANT]-my.sharepoint.com/personal/[USER]_[DOMAIN]_[TLD]/_layouts/15/onedrive.aspx</a> - filling in the specific information within the URL via the username/email and target domain (via --domain).<br /><br />
      * <b>This module currently does not support the --proxy-url flag</b>
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td>
<pre><i>-d/--domain</i>:
Provide the target domain in the form of 'domain.com'.</pre>
    </td>
  </tr>
</table>


### OWA

> OWA User Enumeration

<!-- OWA Enumeration via ActiveSync timing module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/enum/owa_enum_activesync.py">owa_enum_activesync</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> OWA </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td> <a href="https://github.com/fugawi/EASSniper">fugawi: EASSniper</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Identify a baseline response time for invalid users. Then, compare the HTTP response times when requesting <a href="#">https://[url]/Microsoft-Server-ActiveSync</a> with a username (DOMAIN\username) and a password (defaults to 'password') via BasicAuth. Response times lower than the initial baseline are considered as valid.<br/><br/>
      * <b>This performs a single authentication attempt per user</b>
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td>
<pre><i>-d/--domain</i>:
Provide the target domain in the form of 'domain.com' or 'domain' for use with
username formatting via 'DOMAIN\user'.
<br/>
<i>--url</i>:
Provide the target OWA URL in the form of <a href="#">https://target.com/</a>.
Optionally, include '/Microsoft-Server-ActiveSync' - if not included, the module will
automatically append it to the provided URL.</pre>
    </td>
  </tr>
</table>


## Password Spraying

### Microsoft Office 365

> O365 Password Spraying: The default module used by o365spray.py is `o365_spray_activesync`

<!-- O365 Spraying via ActiveSync module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/spray/o365_spray_activesync.py">o365_spray_activesync</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> Microsoft Office 365 / O365 </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td><a href="https://bitbucket.org/grimhacker/office365userenum/src/master/">grimhacker: office365userenum</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the HTTP response status code is '200' when requesting <a href="#">https://outlook.office365.com/Microsoft-Server-ActiveSync</a> with a username/email and a password via BasicAuth.
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td> - </td>
  </tr>
</table>

<br />

<!-- O365 Spraying via ADFS module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/spray/o365_spray_adfs.py">o365_spray_adfs</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> Microsoft Office 365 / O365 </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td><a href="https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py">Mr-Un1k0d3r: adfs-spray</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the HTTP response status code is '302' when requesting the specified ADFS URL (via --url) with a username/email and a password via 'UserName=[USER]&Password=[PASSWORD]&AuthMethod=FormsAuthentication' POST data.
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td>
<pre><i>--url</i>:
Provide the target ADFS URL in the form of <a href="#">https://target.com/...</a></pre>
    </td>
  </tr>
</table>

<br />

<!-- O365 Spraying via MSOL module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/spray/o365_spray_msol.py">o365_spray_msol</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> Microsoft Office 365 / O365 </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td>
        <a href="https://github.com/dafthack/MSOLSpray">dafthack: MSOLSpray</a><br/>
        <a href="https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f">byt3bl33d3r Gist</a>
    </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the HTTP response status code is '200' when requesting <a href="#">https://login.microsoft.com/common/oauth2/token</a> with a username/email and a password via the 'username' and 'password' parameters in the JSON POST data.
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td> - </td>
  </tr>
</table>

### OWA

> OWA Password Spraying

<!-- OWA Spraying via ActiveSync module -->
<table>
  <tr>
    <td> <b>Name</b> </td>
    <td>
      <a href="modules/spray/owa_spray_activesync.py">owa_spray_activesync</a>
    </td>
  </tr>
  <tr>
    <td> <b>Target</b> </td>
    <td> OWA </td>
  </tr>
  <tr>
    <td> <b>Reference(s)</b> </td>
    <td> <a href="https://github.com/fugawi/EASSniper">fugawi: EASSniper</a> </td>
  </tr>
  <tr>
    <td> <b>Technique</b> </td>
    <td>
      Confirm the HTTP response status code is not '401' when requesting <a href="#">https://[url]/Microsoft-Server-ActiveSync</a> with a username (DOMAIN\username) and a password via BasicAuth. Currently, any non-401 HTTP response code will show as a valid credential.
    </td>
  </tr>
  <tr>
    <td> <b>Flags Required</b> </td>
    <td>
<pre><i>-d/--domain</i>:
Provide the target domain in the form of 'domain.com' or 'domain' for use with
username formatting via 'DOMAIN\user'.
<br/>
<i>--url</i>:
Provide the target OWA URL in the form of <a href="#">https://target.com</a>.
Optionally, include '/Microsoft-Server-ActiveSync' - if not included, the module will
automatically append it to the provided URL.</pre>
    </td>
  </tr>
</table>