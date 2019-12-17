<h1 align="center">
  <br>
  <a href="https://github.com/s0md3v/Silver"><img src="https://i.ibb.co/bv3rqXs/silver.png" alt="Silver"></a>
  <br>
  Silver
  <br>
</h1>

<h4 align="center">Mass Vulnerability Scanner</h4>

<p align="center">
  <a href="https://github.com/s0md3v/Silver/releases">
    <img src="https://img.shields.io/github/release/s0md3v/Silver.svg">
  </a>
  <a href="https://github.com/s0md3v/Silver/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/s0md3v/Silver.svg">
  </a>
</p>

### Introduction
masscan is fast, nmap can fingerprint software and vulners is a huge vulnerability database. Silver is a front-end that allows
complete utilization of these programs by parsing data, spawning parallel processes, caching vulnerability data for faster
scanning over time and much more.

![demo](https://i.ibb.co/nPK8yD8/Untitled.png)

> Note: Silver isn't compatible with Python 2.

### Features
- Resumable scanning
- Slack notifcations
- multi-core utilization
- Vulnerability data caching
- Smart Shodan integration*

*\*Shodan integration is optional but when linked, Silver can automatically use Shodan to retrieve service and vulnerability data if a host has a lot of ports open to save resources.
Shodan credits used per scan by Silver can be throttled. The minimum number of ports to trigger Shodan can be configured as well.*

### Requirements
- [nmap](https://nmap.org/)
- [masscan](https://github.com/robertdavidgraham/masscan)

### Usage

> Note: Silver scans all TCP ports by default i.e. ports `0-65535`.

#### Scan host(s) from command line
```
python3 silver.py 127.0.0.1
python3 silver.py 127.0.0.1/22
python3 silver.py 127.0.0.1,127.0.0.2,127.0.0.3
```
##### Scan top ~1000 ports
```
python3 silver.py 127.0.0.1 --quick
```
##### Scan hosts from a file
```
python3 silver.py -i /path/to/targets.txt
```
##### Set max number of parallel nmap instances
```
python3 silver.py -i /path/to/targets.txt -t 4
```

### Configuration
Slack WebHook, Shodan API key and limits can be configured by editing respective variables in `/core/memory.py`

#### Setting up Slack notifications
- Create a workspace on slack, [here](https://slack.com/)
- Create an app, [here](https://api.slack.com/apps/new)
- Enable WebHooks from the app and copy the URL from there to Silver's `/core/memory.py` file.

#### Support the developer
Liked the project? Donate a few bucks to motivate me to keep writing code for free.

[![Donate](https://i.ibb.co/1R5wK5S/28491754-14774f54-6f14-11e7-9975-8a5faeda7e30.gif)](https://s0md3v.github.io/donate.html)


#### Contribution
You can contribute to this project by providing suggestions, reporting sensible issues and spreading the word.
Pull requessts for the following will not be accepted:
- Typos
- coDe qUaLiTY
- Docker and .gitignore file
