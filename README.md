# dead-av 

yo what dis is:  
antivirus/EDR process killer using vulnerable driver

based on [BdApiUtil-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer) 🤷‍♂️

---

## quick start

```bash
# clone it
git clone https://github.com/nw8g/dead-av.git && cd dead-av

# build
make

# place BdApiUtil64.sys next to avk.exe
# run as admin
./avk.exe
````

---

## what it kills

kills 100+ security processes continuously:

* Windows Defender (msmpeng, smartscreen, etc)
* CrowdStrike Falcon variants
* SentinelOne agents
* Carbon Black
* Symantec/Norton/McAfee
* Malwarebytes/Kaspersky/Bitdefender
* Analysis tools
* EDR/SIEM agents (Elastic, Splunk, Tanium, etc)

basically… if it moves and smells like protection, it kills it

---

## how it works

1. loads `BdApiUtil64.sys` as a Windows service
2. scans processes every 2–3 seconds
3. kills targets from kernel space via ioctl `0x800024B4`
4. runs forever until you hit `ctrl+c`

---

## build options

```bash
make            # normal build
make release    # optimized 
make clean      # clean files
```

---

## example output

[![dead-av in action](https://i.postimg.cc/9FTDPRnZ/image.png)](https://postimg.cc/9rmXCMVQ)

---

## requirements

* Windows x64
* Admin privileges
* BdApiUtil64.sys driver file
* g++ or Visual Studio

---


