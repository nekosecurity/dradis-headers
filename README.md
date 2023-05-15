# Description

During one of my experiments, the report contained a presentation of the headers returned by the server.
This tool allows you to display the data before copying/pasting it into the report/generation tool/other tools

## How to use
To use the tool, you just have to provide a burp file and the target whose headers you want.
Example:
```
./dradisheader --scope www.google.com -b google.burp

|Referrer-Policy|Yes|
|Clear-Site-Data|No|
|X-Permitted-Cross-Domain-Policies|No|
|X-Content-Type-Options|Yes|
|Cache-Control|Yes|
|Cross-Origin-Embedder-Policy|Yes|
|X-Frame-Options|Yes|
|Content-Security-Policy|Yes|
|Permission-Policy|No|
|Cross-Origin-Resource-Policy|Yes|
|Strict-Transport-Security|Yes|
|Cross-Origin-Opener-Policy|Yes|

```


## Fun story
Originally, a colleague had the idea of this tool and developed it in Python. It worked very well until it had a large .burp file. At that time, the tool was very slow.

In order to troll, I redeveloped his tool in Rust and a small performance war was born :)

# Todo

A lot of things but nothing will be done because I am not in this configuration anymore.