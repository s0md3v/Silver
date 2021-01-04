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

### Features

- Resumable scanning
- Slack notifcations
- multi-core utilization
- Vulnerability data caching
- Smart Shodan integration\*

_\*Shodan integration is optional but when linked, Silver can automatically use Shodan to retrieve service and vulnerability data if a host has a lot of ports open to save resources.
Shodan credits used per scan by Silver can be throttled. The minimum number of ports to trigger Shodan can be configured as well._

### Setup

#### Downloading Silver

`git clone https://github.com/s0md3v/Silver`

#### Docker build

```sh
docker build --tag silver:latest . && docker run -it silver
```

#### Requirements

##### External Programs

- [nmap](https://nmap.org/)
- [masscan](https://github.com/robertdavidgraham/masscan)

##### Python libraries

- psutil
- requests

Required Python libraries can be installed by executing `pip3 install -r requirements.txt` in `Silver` directory.

#### Configuration

Slack WebHook, Shodan API key and limits can be configured by editing respective variables in `/core/memory.py`

#### Setting up Slack notifications

- Create a workspace on slack, [here](https://slack.com/)
- Create an app, [here](https://api.slack.com/apps/new)
- Enable WebHooks from the app and copy the URL from there to Silver's `/core/memory.py` file.

#### Run it as root

Silver requires root permission because it uses masscan under the hood which needs to be run as root to do port scanning. Use `sudo`.

### Usage

#### Before you start

:warning: Run Silver as root and with `python3` i.e. with `sudo python3 silver.py <your input>`

:warning: Silver scans all TCP ports by default i.e. ports `0-65535`. Use `--quick` switch to only scan top ~1000 ports.

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

#### Contribution

You can contribute to this project by providing suggestions, reporting sensible issues and spreading the word.
Pull requessts for the following will not be accepted:

- Typos
- coDe qUaLiTY
