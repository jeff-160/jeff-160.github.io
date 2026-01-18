---
title: "Gryphons CTF 2025 Web walkthrough"
date: 2025-11-04
summary: "writeups for gctf 2025 web challs"
tags: ["gctf", "ctf", "web"]
---

I recently participated in Gryphons CTF 2025 with [Mengxiang](https://github.com/mengxiang1), [Ernest](https://github.com/Techie-Ernie) and [Xizhen](https://github.com/burner972021).  

<img src="/blog/gctf_2025_web_walkthrough/images/team.png" width=800>

We finished 3rd place overall, tying for 1st in points. I also got my first web FC so I figured I'd do a chall walkthrough.  

<img src="/blog/gctf_2025_web_walkthrough/images/fc.png" width=800>


## Kid named Jason

<img src="/blog/gctf_2025_web_walkthrough/images/kid_named_jason/chall.png" width=400>

The webpage we are provided with gives us some instructions.  

<img src="/blog/gctf_2025_web_walkthrough/images/kid_named_jason/webpage.png" width=400>

Visiting the `/token` endpoint does indeed give us a sample token.  

<img src="/blog/gctf_2025_web_walkthrough/images/kid_named_jason/token.png" width=600>

When we try visiting the `/verify` endpoint with our token we get this error.  

```
{"error":"The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.","file_leak":"-----BEGIN PUBLIC KEY-----\nFAKEPUBLICKEY\n-----END PUBLIC KEY-----\n","ok":false}
```

The first thing we may notice is that the error message has a `file_leak` parameter, and the contents of a public key file seem to be outputted.  

Decoding the JWT token from Base64 shows a `kid` parameter in the token header containing the path to a public key.  

<img src="/blog/gctf_2025_web_walkthrough/images/kid_named_jason/jwt.png" width=500>

This points towards an LFI vulnerability. When we change `kid` to a known file like `/etc/passwd`, the server does indeed return the file's contents.  

<img src="/blog/gctf_2025_web_walkthrough/images/kid_named_jason/lfi.png" width=800>

This means that if we are able to locate the flag file, we can get the server to output it and print out the flag.  

After some guesses, I found it in `/flag.txt`.  

<img src="/blog/gctf_2025_web_walkthrough/images/kid_named_jason/flag.png" width=600>

Flag: `GCTF25{t0ken_of_4ppreciation}`


## Pantone

<img src="/blog/gctf_2025_web_walkthrough/images/pantone/chall.png" width=400>

We are given a webpage where we can mix colors.  

<img src="/blog/gctf_2025_web_walkthrough/images/pantone/webpage.png" width=400>

In the source code, the flag is stored as a global variable.  

<img src="/blog/gctf_2025_web_walkthrough/images/pantone/source_flag.png" width=500>

We can also notice that there's a prototype pollution vulnerability in one of the functions.  

<img src="/blog/gctf_2025_web_walkthrough/images/pantone/vuln.png" width=500>

In the `/colors` endpoint, there's an `eval()` call which we can potentially hijack to get RCE.  

<img src="/blog/gctf_2025_web_walkthrough/images/pantone/colors.png" width=400>

We can easily craft a payload that will cause the vulnerable function to recursively traverse to the global scope, where we can then overwrite `_EXEC_CMD` to `flag`.  

<img src="/blog/gctf_2025_web_walkthrough/images/pantone/payload.png" width=400>

Sending the payload to the `/colors` endpoint will then cause the server to output the flag.  

Flag: `GCTF25{COL0Rfu1_C!a55_polLU71ON}`


## treasure hunt

<img src="/blog/gctf_2025_web_walkthrough/images/treasure_hunt/chall.png" width=400>

We are given a webpage where we can submit our name for a greeting message.  

<img src="/blog/gctf_2025_web_walkthrough/images/treasure_hunt/webpage.png" width=500>

The greeting message hints that there is an SSTI vulnerability within the webpage.  

<img src="/blog/gctf_2025_web_walkthrough/images/treasure_hunt/hint.png" width=500>

Running a simple Python SSTI payload shown below gave an error, which revealed that the server used Node.js Nunjucks for templating rather than Jinja.  

```python
{{ self.__init__.__globals__.__builtins__['__import__']('os') }}
```

<img src="/blog/gctf_2025_web_walkthrough/images/treasure_hunt/error.png" width=800>

With this knowledge, we can craft a simple payload that gives us RCE on the webpage.  

```javascript
{{ range.constructor('return process')().mainModule.require('child_process').execSync('ls').toString() }}
```

Running `ls` then reveals the entire directory structure.  

<img src="/blog/gctf_2025_web_walkthrough/images/treasure_hunt/files.png" width=400>

To spare you the details, we have to read `flags/part1.txt`, `flags/secret.bat`, `part2.txt` and `server.js` to retrieve and reassemble all parts of the flag.  

Flag: `GCTF25{5STI_p47H_7Rav3R5A1_M45teR}`


## TypeFinder!

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/chall.png" width=400>

We are given a webpage with some additional functionalities.  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/webpage.png" width=400>

In the `forgor.php` page, we can confirm that an admin account does indeed exist on the server.  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/forgor.png" width=500>

We also have a file viewer page, which hints that there is a list of accounts on the server, but there's no instructions on how to use it. However, judging from the fact that `forgor.php` uses `q` for arguments, a reasonable guess would be that `view.php` uses `f` for file arguments.  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/view.png" width=600>

That indeed works, and we are able to view the source code of `view.php`. From this, we learn that there is a whitelist of readable files, and `users.json` is indeed among them.  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/view_php.png" width=500>

Viewing the source code for `login.php` also reveals the exact location of `users.json`.  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/login_php.png" width=400>

Since `users.json` and the `.php` files are in different directories, we have to use path traversal to access it.  

```
http://chal1.gryphons.sg:8004/view.php?f=../../private/users.json
```

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/users.png" width=500>

Recalling the source code for `login.php`, the login page actually checks the MD5 hash of our entered password against the password stored on the server, so we can't just login with `0e462097431906509019562988736854` directly.  

However, we can simply get the preimage of the MD5 hash using [md5decrypt](https://md5decrypt.net/).  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/md5decrypt.png" width=600>

Logging in with `admin` and `240610708` does indeed output the flag.  

<img src="/blog/gctf_2025_web_walkthrough/images/typefinder/flag.png" width=400>

Flag: `GCTF25{TypE_jugg13_th3$E_nuT$}`


## Gryphons Site

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/chall.png" width=400>

We are given a webpage containing information about the Gryphons team members.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/webpage.png" width=600>

There is also an admin login page, but all attempts at SQLi fail, so the login can't be that straightforward.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/admin.png" width=400>

Going back to the team page, I found out that member information is fetched using `/members?id=1`.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/query.png" width=500>

Looking at the HTML source of one of the member pages, I found a suspiciously empty div.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/div.png" width=400>

I also found out that it is possible to leak errors when tampering with the `id` parameter in `/members`. Below was the message I got when I set it to `0`.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/leak.png" width=600>

Replacing `id` with an SQLi payload like `'--` gave a different error, which proved that the endpoint was vulnerable to SQLi.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/db.png" width=600>

Since this is essentially a blind SQLi, the most logical thing to do would be to leak the database structure and table information.  

Through trial and error, I was able to produce a working payload that leaked the structure of the first table in the database.  

```sql
0 union select sql,null,null,null,null,null from sqlite_master where type="table"
```

I wrote a Python script to bruteforce all possible tables by incrementing the `OFFSET` in the union attack.  

One of the tables leaked was `creds`, which could potentially contain all login credentials.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/creds.png" width=500>

By tweaking the payload a bit, I was able to leak all the accounts from `creds`.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/accounts.png" width=500>

My teammate was able to crack weiyan's password hash using `hashcat`, revealing that her password was `maple`.

Using the credentials, I was finally able to login to the admin dashboard.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/dashboard.png" width=600>

The flag wasn't in any of the pages on the dashboard, but I did manage to find a potential LFI vulnerability.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/lfi.png" width=600>

After some guesses, I found a file called `flag.html`, which displayed the Base64-encoded flag.  

<img src="/blog/gctf_2025_web_walkthrough/images/gryphons_site/flag.png" width=600>

Flag: `GCTF25{welcome_to_gryphons}`


