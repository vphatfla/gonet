# gonet

Port Scanner for Network Vulnerability

## Usage

Must compile and run the binary as root

Example running scan against server outlook.com

```
go build && sudo ./gonet
2025/04/17 14:10:12 Welcome to go net
Enter IP4 address 52.96.229.242
2025/04/17 14:10:13 Start scanning all port from 0 to 65535
2025/04/17 14:10:16 Timeout after 3 seconds
2025/04/17 14:10:16 Port 25(smtp) status OPEN ---Scan takes 186.170542ms
2025/04/17 14:10:16 Port 80(http) status OPEN ---Scan takes 185.048165ms
2025/04/17 14:10:16 Port 110(pop3) status OPEN ---Scan takes 217.369248ms
2025/04/17 14:10:16 Port 143(imap) status OPEN ---Scan takes 216.72778ms
2025/04/17 14:10:16 Port 443(https) status OPEN ---Scan takes 141.915058ms
2025/04/17 14:10:16 Port 993(imaps) status OPEN ---Scan takes 330.977721ms
2025/04/17 14:10:16 Port 995(pop3s) status OPEN ---Scan takes 330.954008ms
2025/04/17 14:10:16 Port 587(submission) status OPEN ---Scan takes 679.338655ms
2025/04/17 14:10:16 Closing scanner

```
## Support

This scanner currently only support Linux OS.
