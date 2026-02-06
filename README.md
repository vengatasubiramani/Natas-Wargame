## OverTheWire Natas Wargame – Progress & Learning Journey

I have successfully completed the OverTheWire **Natas Wargame up to Level 30** through structured research, deep technical analysis, and hands-on experimentation.

Each challenge was solved by understanding the underlying vulnerability rather than simply viewing solutions. I studied technical documentation, research articles, blogs, and open-source references to analyze how each web application functioned internally before developing a working exploit.

### 💡 Skills Strengthened

-   Web application vulnerability analysis
    
-   SQL injection & parameter manipulation
    
-   Cryptographic attack concepts (CBC block manipulation, encoding flaws)
    
-   Server-side logic exploitation
    
-   Practical debugging and security testing
    

This journey significantly strengthened my problem-solving ability, research skills, and practical understanding of real-world cybersecurity concepts.

# 🏁 Natas Level 00: The Basics of Web Pages

**URL:** `http://natas0.natas.labs.overthewire.org` 

**Credentials:** `natas0` : `natas0`

### 💡 The Concept

Web applications are built using HTML (HyperText Markup Language). Developers use comments (`<!-- comment -->`) to document their code or leave reminders. These comments are not rendered on the visible page but are sent to the user's browser in the source code.

### 🔍 Technical Explanation

When you request a page, the server sends the full HTML file. If a developer forgets to remove sensitive information (like credentials) from comments, any user can see them by inspecting the "Source" of the page.

### 🚀 How to solve

1.  Open the URL and log in.
    
2.  Right-click on the page and select **View Page Source**.
    
3.  Scan the code for an HTML comment containing the password.
    

**Password for Natas 01:** `0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`

# 🏁 Natas Level 01: Bypassing Client-Side Restrictions

**URL:** `http://natas1.natas.labs.overthewire.org` 

**Credentials:** `natas1` : `0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`

### 💡 The Concept

"Client-side" security refers to restrictions implemented in the browser using JavaScript or HTML attributes. Because the user has full control over their browser environment, these restrictions are purely cosmetic and offer no real security.

### 🔍 Technical Explanation

In this level, the developers used JavaScript to intercept the `contextmenu` event (right-click). However, the source code is still delivered to your machine. You can bypass this by using browser shortcuts that the script cannot block.

### 🚀 How to solve

1.  Since right-click is disabled, use the keyboard shortcut:
    
    -   **Windows/Linux:** `Ctrl + U`
        
    -   **Mac:** `Cmd + Option + U`
        
2.  Alternatively, add `view-source:` before the URL in your address bar.
    

**Password for Natas 02:** `TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`

# 🏁 Natas Level 02: Information Leakage & Directory Indexing

**URL:** `http://natas2.natas.labs.overthewire.org` 

**Credentials:** `natas2` : `TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`

### 💡 The Concept

Information leakage occurs when a web server reveals sensitive data, such as file structures or configuration files. Directory Indexing is a feature where a server displays a list of all files in a folder if no `index.html` file is present.

### 🔍 Technical Explanation

By examining the source code, you find a reference to a file path: `files/pixel.png`. By removing the filename, you can check if the `/files/` directory allows indexing. If it does, you can see all other files stored in that same directory.

### 🚀 How to solve

1.  View the page source and find the path to the image.
    
2.  Navigate to `http://natas2.natas.labs.overthewire.org/files/`.
    
3.  Locate and open the `users.txt` file.
    

**Password for Natas 03:** `3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`

# 🏁 Natas Level 03: Hidden in Plain Sight (Robots.txt)

**URL:** `http://natas3.natas.labs.overthewire.org` 

**Credentials:** `natas3` : `3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`

### 💡 The Concept

The `robots.txt` file is a standard used by websites to communicate with web crawlers (like Googlebot). It tells them which parts of the site should not be indexed. However, it is a public file that anyone can read.

### 🔍 Technical Explanation

Developers often think that "Disallowing" a folder in `robots.txt` makes it secret. In reality, it provides a "map" for attackers to find hidden directories that the developers don't want people to see.

### 🚀 How to solve

1.  Access the file at `http://natas3.natas.labs.overthewire.org/robots.txt`.
    
2.  Find the "Disallow" entry for `/s3cr3t/`.
    
3.  Navigate to that directory and open `users.txt`.
    

**Password for Natas 04:** `QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`

# 🏁 Natas Level 04: Spoofing the Referer Header

**URL:** `http://natas4.natas.labs.overthewire.org` 

**Credentials:** `natas4` : `QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`

### 💡 The Concept

The `Referer` HTTP request header contains the address of the previous web page from which a link to the currently requested page was followed. Some servers use this for basic authentication or access control.

### 🔍 Technical Explanation

The server checks if your `Referer` header matches `http://natas5.natas.labs.overthewire.org/`. Since HTTP headers are sent by the client (your browser), they can be easily manipulated (spoofed) to trick the server into thinking you came from a trusted source.

### 🚀 How to Solve

1.  Use a browser extension (like "ModHeader") or a tool like Burp Suite.
    
2.  Add or modify the header: `Referer: http://natas5.natas.labs.overthewire.org/`.
    
3.  Refresh the page with the modified header.
    

**Password for Natas 05:** `0n35PkggAPm2zbEpOU802c0x0Msn1ToK`

# 🏁 Natas Level 05: Manipulating Session Cookies

**URL:** `http://natas5.natas.labs.overthewire.org` 

**Credentials:** `natas5` : `0n35PkggAPm2zbEpOU802c0x0Msn1ToK`

### 💡 The Concept

Cookies are small data packets stored in the user's browser. They are often used to track login states. If a developer uses a simple, predictable cookie value to check if a user is "logged in," it can be easily altered.

### 🔍 Technical Explanation

The server sends a cookie `loggedin=0`. On subsequent visits, it checks this value. By changing the value to `1`, we bypass the check. Real-world applications should use encrypted session IDs rather than simple flags.

### 🚀 How to Solve

1.  Open Developer Tools (F12) -> **Application** -> **Cookies**.
    
2.  Change the value of the `loggedin` cookie from `0` to `1`.
    
3.  Refresh the page.
    

**Password for Natas 06:** `0RoJwHdSKWFTYR5WuiAewauSuNaBXned`

# 🏁 Natas Level 06: Reading Server-Side Secret Files

**URL:** `http://natas6.natas.labs.overthewire.org` 

**Credentials:** `natas6` : `0RoJwHdSKWFTYR5WuiAewauSuNaBXned`

### 🔍 Source Code

```
<?php
include "includes/secret.inc";
if(array_key_exists("submit", $_POST)) {
    if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
}
?>

```

### 🚀 How to solve

1.  The code includes `includes/secret.inc`.
    
2.  Visit `http://natas6.natas.labs.overthewire.org/includes/secret.inc`.
    
3.  View the source to see the secret value: `$secret = "FOEIUWGHFEEUHOFUOIU";`.
    
4.  Submit this secret on the main page.
    

**Password for Natas 07:** `bmg8SvU1LizuWjx3y7xkNERkHxGre0GS`

# 🏁 Natas Level 07: Local File Inclusion (LFI)

**URL:** `http://natas7.natas.labs.overthewire.org`

**Credentials:** `natas7` : `bmg8SvU1LizuWjx3y7xkNERkHxGre0GS`

### 💡 The Concept

Local File Inclusion (LFI) is a vulnerability where an application allows a user to specify which file the server should include or execute. This usually happens when input to a file-handling function is not properly sanitized.

### 🔍 Technical Explanation

The URL `index.php?page=home` suggests that the `page` parameter is used to determine which file to display. We can provide an absolute path to a sensitive file on the Linux server (like the Natas password storage) to read it.

### 🚀 How to solve

1.  Modify the URL to: `index.php?page=/etc/natas_webpass/natas8`
    

**Password for Natas 08:** `xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`

# 🏁 Natas Level 08: Reversing Weak Encoding

**URL:** `http://natas8.natas.labs.overthewire.org`

**Credentials:** `natas8` : `xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`

### 🔍 Source Code

```
<?php
$encodedSecret = "3d3d516343746d4d6d6c315669563362";
function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}
?>

```

### 🚀 How to Solve

1.  Take the hex string `3d3d516343746d4d6d6c315669563362`.
    
2.  Convert it from Hex to text.
    
3.  Reverse the resulting string.
    
4.  Decode the result from Base64 to get `oubWYf2kBq`.
    

**Password for Natas 09:** `ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t`

# 🏁 Natas Level 09: Command Injection

**URL:** `http://natas9.natas.labs.overthewire.org` 

**Credentials:** `natas9` : `ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t`

### 🔍 Source Code

```
<?php
$key = "";
if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}
if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>

```

### 🚀 How to solve

1.  In the search box, enter: `; cat /etc/natas_webpass/natas10`
    
2.  This forces the server to run `grep -i ;` followed by `cat /etc/natas_webpass/natas10`.
    

**Password for Natas 10:** `t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu`

# 🏁 Natas Level 10: Advanced Command Injection (Filter Bypass)

**URL:** `http://natas10.natas.labs.overthewire.org` 

**Credentials:** `natas10` : `t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu`

### 🔍 Source Code

```
<?php
$key = "";
if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}
if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>

```

### 🚀 How to solve

1.  Semicolons are blocked. However, `grep` can search multiple files if you just add a space.
    
2.  Enter this in the search box: `.* /etc/natas_webpass/natas11`
    
3.  The server runs: `grep -i .* /etc/natas_webpass/natas11 dictionary.txt`.
    
**Password for Natas 11:** `UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk'

## 🏁 Natas Level 11: XOR Encryption & Known Plaintext Attack

**URL:** http://natas11.natas.labs.overthewire.org

**Credentials:** `natas11` : `UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk`

**💡 The Concept** XOR encryption is a simple mathematical operation. A major weakness is that if you have the **Original Data** (Plaintext) and the **Encrypted Result** (Ciphertext), you can mathematically calculate the **Secret Key**. Once you have the key, you can forge your own data.

**🚀 How to solve**

1.  The PHP source shows the site uses a cookie named `data` to store preferences.
    
2.  The default data is `{"showpassword":"no", "bgcolor":"#ffffff"}`.
    
3.  Because XOR is reversible, we take that default JSON string and XOR it against the base64-decoded cookie from the browser to find the key: `qw8J`.
    
4.  We then create a new JSON string: `{"showpassword":"yes", "bgcolor":"#ffffff"}`, encrypt it using the key `qw8J`, and update our cookie.
    

**Password for Natas 12:** `yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB`

## 🏁 Natas Level 12: Insecure File Upload

**URL:** http://natas12.natas.labs.overthewire.org

**Credentials:** `natas12` : `yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB`

**💡 The Concept** Websites often allow users to upload images. A vulnerability exists if the server doesn't check the _type_ of file on the server-side, allowing a user to upload a script (like PHP) that the server will execute.

**🚀 How to solve**

1.  Create a file named `shell.php` with this content: `<?php echo passthru("cat /etc/natas_webpass/natas13"); ?>`.
    
2.  On the upload page, notice a hidden HTML field: `<input type="hidden" name="filename" value="xyz.jpg">`.
    
3.  Use a proxy (like Burp Suite) or Inspect Element to change that value from `xyz.jpg` to `xyz.php` before clicking upload.
    
4.  Click the link to your uploaded file to see the password.
    

**Password for Natas 13:** `trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC`

## 🏁 Natas Level 13: Bypassing Image Validation (Magic Bytes)

**URL:** http://natas13.natas.labs.overthewire.org

**Credentials:** `natas13` : `trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC`

**💡 The Concept** The server now uses `exif_imagetype()` to check if the file is an image. This function looks at the "Magic Bytes" (the first few bytes) of a file. If we put image headers at the start of our PHP script, the server is tricked.

**🚀 How to solve**

1.  Take your PHP script from Level 12.
    
2.  Add the hex bytes for a JPEG or the text `GIF89a` at the very top of the file.
    
3.  Upload it, rename the extension to `.php` via a proxy as done previously, and execute it.
    

**Password for Natas 14:** `z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ`

## 🏁 Natas Level 14: SQL Injection (Auth Bypass)

**URL:** http://natas14.natas.labs.overthewire.org

**Credentials:** `natas14` : `z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ`

**💡 The Concept** SQL Injection happens when user input is placed directly into a database query. By using special characters, we can change the logic of the query to always return "True."

**🚀 How to solve**

1.  The query looks for a username and password.
    
2.  In the username field, enter: `admin" OR 1=1--`
    
3.  The `"` closes the username string, `OR 1=1` makes the condition always true, and `--` comments out the rest of the password check.
    

**Password for Natas 15:** `SdqIqBsFcz3yotlNYErZSZwblkm0lrvx`

## 🏁 Natas Level 15: Blind SQL Injection

**URL:** http://natas15.natas.labs.overthewire.org

**Credentials:** `natas15` : `SdqIqBsFcz3yotlNYErZSZwblkm0lrvx`

**💡 The Concept** "Blind" SQLi occurs when the page doesn't show database data, only a "True" or "False" message (like "User exists"). We can leak the password by asking the database "Yes/No" questions for every character.

**🚀 How to solve**

1.  Use an injection like: `natas16" AND password LIKE BINARY "a%`.
    
2.  If the page says "This user exists," the password starts with 'a'.
    
3.  Automate this with a script to check every character (a-z, A-Z, 0-9) until the 32-character password is rebuilt.
    

**Password for Natas 16:** `hPkjKYviLQctEW33QmuXL6eDVfMW4sGo`

## 🏁 Natas Level 16: Blind Command Injection

**URL:** http://natas16.natas.labs.overthewire.org

**Credentials:** `natas16` : `hPkjKYviLQctEW33QmuXL6eDVfMW4sGo`

**💡 The Concept** This level uses `grep` to search a dictionary. By using `$(...)`, we can run a command inside the search. If the "inner" command finds something, it changes the results of the "outer" command.

**🚀 How to solve**

1.  Inject: `$(grep ^a /etc/natas_webpass/natas17)`.
    
2.  If the password for Natas 17 starts with 'a', the dictionary search becomes empty (returning no results).
    
3.  By watching if the dictionary results disappear, we can figure out the password character by character.
    

**Password for Natas 17:** `EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC`

## 🏁 Natas Level 17: Time-Based Blind SQLi

**URL:** http://natas17.natas.labs.overthewire.org

**Credentials:** `natas17` : `EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC`

**💡 The Concept** When a page gives no visual feedback at all, we use "Time-Based" injection. We tell the database: "If the first letter is 'a', wait 5 seconds before responding."

**🚀 How to solve**

1.  Inject: `natas18" AND IF(password LIKE BINARY "a%", SLEEP(5), 1)--` .
    
2.  If the website takes 5 seconds to load, you know the character 'a' is correct.
    

**Password for Natas 18:** `6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ`

## 🏁 Natas Level 18: Predictable Session IDs

**URL:** http://natas18.natas.labs.overthewire.org

**Credentials:** `natas18` : `6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ`

**💡 The Concept** Session IDs (PHPSESSID) identify your login. If these IDs are simple numbers (1, 2, 3...), you can guess the ID of another user—like the Admin.

**🚀 How to solve**

1.  The code shows the Max ID is 640.
    
2.  Use a script to refresh the page 640 times, each time changing your `PHPSESSID` cookie to a new number.
    
3.  One of those IDs belongs to the admin, and the page will show you the password.
    

**Password for Natas 19:** `tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr`

## 🏁 Natas Level 19: Hex-Encoded Session IDs

**URL:** http://natas19.natas.labs.overthewire.org

**Credentials:** `natas19` : `tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr`

**💡 The Concept** This is like Level 18, but the ID looks like random letters and numbers. It is actually just text converted to "Hexadecimal" format.

**🚀 How to solve**

1.  Inspect your cookie; it might look like `3135322d61646d696e`.
    
2.  Decoding it reveals `152-admin`.
    
3.  Bruteforce the numbers (1-640) again, but encode them as `[number]-admin` in Hex before sending the cookie.
    

**Password for Natas 20:** `p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw`

## 🏁 Natas Level 20: Session Poisoning

**URL:** http://natas20.natas.labs.overthewire.org

**Credentials:** `natas20` : `p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw`

**💡 The Concept** The server saves session data in a text file, one variable per line. If the server doesn't clean your input, you can insert a "New Line" character to write your own variables into the session file.

**🚀 How to solve**

1.  The server asks for your name. Enter: `admin\nadmin 1`.
    
2.  When the server saves this, it writes `name admin` on one line and `admin 1` on the next.
    
3.  When the server reads the file back, it thinks `admin = 1` is a valid session setting, giving you admin rights.
    

**Password for Natas 21:** `BPhv63cKE1lkQl04cE5CuFTzXe15NfiH`

## 🏁 Natas Level 21: Co-located Session Vulnerability

**URL:** http://natas21.natas.labs.overthewire.org

**Credentials:** `natas21` : `BPhv63cKE1lkQl04cE5CuFTzXe15NfiH`

**💡 The Concept** Multiple websites on the same server might share the same session storage directory. If one site lets you modify session variables and the other trusts those variables, you can pivot between them.

**🚀 How to solve**

1.  Visit the "experimenter" site: `http://natas21-experimenter.natas.labs.overthewire.org`.
    
2.  Submit a request that adds `admin=1` to your session: `?submit=1&admin=1`.
    
3.  Take the `PHPSESSID` cookie from that site and use it on the main Natas 21 page.
    

**Password for Natas 22:** `d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz`

## 🏁 Natas Level 22: Header Redirect Bypass

**URL:** http://natas22.natas.labs.overthewire.org

**Credentials:** `natas22` : `d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz`

**💡 The Concept** PHP's `header("Location: ...")` doesn't stop the script from running; it just sends a redirect instruction to the browser. If the code continues to execute and print data after the header call, a client that ignores the redirect (like `curl` or Burp) will see it.

**🚀 How to solve**

1.  Access the URL with the `revelio` parameter: `?revelio=1`.
    
2.  Use a tool that doesn't follow redirects automatically, or check the response body in Burp Suite despite the 302 status.
    

**Password for Natas 23:** `dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs`

## 🏁 Natas Level 23: PHP Type Juggling & strstr()

**URL:** http://natas23.natas.labs.overthewire.org

**Credentials:** `natas23` : `dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs`

**💡 The Concept** The code checks if a string contains "iloveyou" and if the input, when treated as a number, is greater than 10. PHP's loose typing allows a string starting with a number to be evaluated as that number in numeric comparisons.

**🚀 How to solve**

1.  Provide an input like `11iloveyou`.
    
2.  `strstr()` finds "iloveyou" (True), and `11iloveyou > 10` evaluates to `11 > 10` (True).
    

**Password for Natas 24:** `MeuqmfJ8DDKuTr5pcvzFKSwlxedZYEWd`

## 🏁 Natas Level 24: strcmp() Array Vulnerability

**URL:** http://natas24.natas.labs.overthewire.org

**Credentials:** `natas24` : `MeuqmfJ8DDKuTr5pcvzFKSwlxedZYEWd`

**💡 The Concept** In older versions of PHP, if you pass an array to `strcmp()` instead of a string, it returns `0` (indicating a match) even though it also throws a warning.

**🚀 How to solve**

1.  Change the input name from `passwd` to `passwd[]`.
    
2.  Submit `http://natas24.natas.labs.overthewire.org/?passwd[]=anyvalue`.
    

**Password for Natas 25:** `ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws`

## 🏁 Natas Level 25: LFI & Log Poisoning

**URL:** http://natas25.natas.labs.overthewire.org

**Credentials:** `natas25` : `ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws`

**💡 The Concept** The app allows file inclusion through a `lang` parameter but tries to filter `../`. However, it only does one pass of replacement. By using `....//`, it becomes `../`. We can then include the server's own logs, which we poison with PHP code via our User-Agent.

**🚀 How to solve**

1.  Find your `PHPSESSID`.
    
2.  Change your User-Agent to: `<?php echo file_get_contents('/etc/natas_webpass/natas26'); ?>`.
    
3.  Include the log file: `?lang=....//....//....//....//var/www/natas/natas25/logs/natas25_[YOUR_SESSION_ID].log`.
    

**Password for Natas 26:** `cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE`

## 🏁 Natas Level 26: PHP Object Injection (Insecure Deserialization)

**URL:** http://natas26.natas.labs.overthewire.org

**Credentials:** `natas26` : `cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE`

**💡 The Concept** The site uses `unserialize()` on a base64-encoded cookie. We can forge a cookie containing a serialized object of the `Logger` class, manipulating its properties to write a PHP shell to a reachable directory when the object is destroyed.

**🚀 How to solve**

1.  Create a PHP script locally that defines the `Logger` class but sets `$logFile` to `img/shell.php` and `$exitMsg` to a payload reading the natas27 pass.
    
2.  Serialize this object, base64 encode it, and set it as your `drawing` cookie.
    
3.  Access `img/shell.php` to see the result.
    

**Password for Natas 27:** `u3RRffXjysjgwFU6b9xa23i6prmUsYne`

## 🏁 Natas Level 27: SQL Truncation Attack

**URL:** http://natas27.natas.labs.overthewire.org

**Credentials:** `natas27` : `u3RRffXjysjgwFU6b9xa23i6prmUsYne`

**💡 The Concept** MySQL sometimes truncates strings that exceed the column length (64 chars) during insertion. By registering a user named `natas28` followed by 64 spaces and a dummy character, MySQL truncates it to just `natas28`.

**🚀 How to solve**

1.  Register a user with username: `natas28` + 64 spaces + `x`.
    
2.  Use any password.
    
3.  Log in normally as `natas28` with that password. Since the original admin `natas28` exists, and your new truncated entry also exists, the query returns the admin data.
    

**Password for Natas 28:** `1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj`

## 🏁 Natas Level 28: ECB Chosen Plaintext Attack

**URL:** http://natas28.natas.labs.overthewire.org

**Credentials:** `natas28` : `1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj`

**💡 The Concept** The search query is encrypted using AES-ECB. ECB encrypts identical blocks of plaintext into identical blocks of ciphertext. By observing how the ciphertext changes with different input lengths, we can identify where our input starts and perform a "bit-flipping" or block-shuffling attack to inject SQL.

**🚀 How to solve**

1.  Use a script to determine the block size (16 bytes).
    
2.  Identify that the query is likely `SELECT * FROM table WHERE column LIKE '%YOUR_INPUT%'`.
    
3.  Forge a ciphertext by swapping or repeating blocks to bypass the escaping of the single quote.
    

**Password for Natas 29:** `31F4j3Qi2PnuhIZQokxXk1L3QT9Cppns`

## 🏁 Natas Level 29: Perl Command Injection

**URL:** http://natas29.natas.labs.overthewire.org 

**Credentials:** `natas29` : `31F4j3Qi2PnuhIZQokxXk1L3QT9Cppns`

**💡 The Concept** The application uses a Perl script to open files. In Perl, the `open()` function can execute commands if the filename starts or ends with a pipe (`|`). By injecting a pipe, we can execute arbitrary shell commands.

**🚀 How to solve**

1.  Inject a pipe and a command into the `file` parameter: `?file=|ls`.
    
2.  To bypass the "natas" keyword filter when reading the password, use shell quoting: `?file=|cat+/etc/na""tas_webpass/nat""as30`.
    
3.  Use a null byte `%00` if needed to terminate the `.txt` extension append.
    

**Password for Natas 30:** `WQhx1BvcmP9irs2MP9tRnLsNaDI76YrH`

## 🏁 Natas Level 30: Perl DBI Quote Vulnerability

**URL:** http://natas30.natas.labs.overthewire.org 

**Credentials:** `natas30` : `WQhx1BvcmP9irs2MP9tRnLsNaDI76YrH`

**💡 The Concept** Perl's `DBI->quote()` method behaves unexpectedly when passed an array instead of a string. Passing an array can bypass the quoting mechanism, allowing for SQL injection or logic manipulation.

**🚀 How to solve**

1.  Send a POST request where the `password` parameter is an array rather than a single string.
    
2.  In Python: `data = {"username": "natas31", "password": ["'' or 1", 2]}`.
    
3.  This forces the query to return true for the admin user.
    

**Password for Natas 31:** `m7bfjAHpJmSYgQWWeqRE2qVBuMiRNq0y`
