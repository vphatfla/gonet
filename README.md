# gonet

Port Scanner for Network Vulnerability

## Usage

CLI install:

```
go install

sudo cp ~/go/bin/gonet /usr/local/bin

sudo gonet ...

```
Must compile and run the binary as root

Example running scan against server outlook.com

```
sudo gonet -i 52.96.91.34 -wkn
Scanning well-knowns ports [0...1023]
2025/04/21 15:03:16 Timeout after 3 seconds
Port 25(smtp) --> Status OPEN ---  Scan takes 110.72296ms
Port 110(pop3) --> Status OPEN ---  Scan takes 121.247065ms
Port 80(http) --> Status OPEN ---  Scan takes 121.402156ms
Port 143(imap) --> Status OPEN ---  Scan takes 121.103664ms
Port 443(https) --> Status OPEN ---  Scan takes 110.957307ms
Port 587(submission) --> Status OPEN ---  Scan takes 116.198241ms
Port 993(imaps) --> Status OPEN ---  Scan takes 127.266459ms
Port 995(pop3s) --> Status OPEN ---  Scan takes 138.238413ms
```

## Support

This scanner currently only support Linux OS.
