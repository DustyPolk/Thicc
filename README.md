# Welcome to Thicc 
Thicc is a fast web application reconnaissance tool written in Rust for ethical hackers. The purpose was to have a project to start learning rust that could also perhaps help other people. I'm not saying you should use this over any of the other clearly better solutions out there, however some people may find a use for it :) I welcome any and all comments. I plan to work on this frequently.

![RuFi/RustFinder](rufi.gif

# Use
```
    -d, --dirs <DirEnum>      Directory Enumuration [requires -w flag]
    -g, --geo <GeoIP>         GeoLocation for IPv4
    -h, --help                Print help information
    -p, --ports <PortScan>    Scans for open ports
    -r, --dns <DNS>           DNS Resolver
    -s, --subs <SubEnum>      Subdomain Enumuration [requires -w flag]
    -w, --words <wordlist>    Wordlist input, use full path
                              Example: -w /home/youruser/dir.txt
```

# Version
**0.2 [ALPHA]**

# What's To Come?
- Progress Bars
- Spider
- Technology Stack Detection

# Documentation
Directory Enumeration
```./rufi -d https://127.0.0.1 -w /home/youruser/dirlist.txt```

Sub Domain Enumeration
```./rufi -s https://127.0.0.1 -w /home/youruser/sublist.txt```

Port Scanner
```./rufi -p 127.0.0.1```

DNS Resolver
```./rufi -r https://127.0.0.1```

GeoIP Location
```./rufi -g 127.0.0.1```

# License
This work is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License. You may use this software anyway you like, but you may not profit off this work. Open Source/Freeware FTFW

# Changelog
5/5/2022: Added service enumeration to the port scanner

21/04/2022: 0.2 released, port scanner added


