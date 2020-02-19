```
                 __                                      
  ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___ 
 / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \
/ /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /
\__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/ 
                                                         
```
## Summary
Autoenum is a recon tool which performs automatic enumeration of services discovered. I built this to save some time during CTFs and pen testing environments (i.e. HTB, VulnHub, OSCP). Could also be used in a real-life pentesting engagment. Currently has only been tested in kali. If you notice a bug or have a feature request not in to-do, please submit an issue. Thanks and enjoy autoenum!  

## How it Works
Autoenum draws ideas from a a few tools (AutoRecon, nmapautomator, and sumrecon). Started as a challenge that turned into a full project. Autoenum first runs 2 nmap scans in tandem, one scan looks specifically for service versions to run against searchsploit and the other is a scan dependent on the argument. Every scan profile checks for services running, the type of scan is the only difference. After the scans are finished, the services/ports open and operating systems along with script output ( if avaliable) is extracted and further analyzed. If a certain service is found, Autoenum will begin enumerating by firing off a number of tools and create a dir for that service (i.e detecting http starts up nikto, wafw00f, gobuster, and others). If a dependency required is not detected, that dependency will be auto installed and checked if there is a new update everytime the tool is run. Autoenum outputs this information in 2 main sections(scan type and loot dirs) with sub directories branching off depending on what is found.

## Dependencies
Your OS may or may not have some installed by default. Not to worry, autoenum recognizes tools not installed and installs them for you, even updating if they aren't up-to-date!

* nmap
* nikto
* gobuster
* whatweb
* onesixtyone
* snmp-check
* snmpwalk
* fierce
* dnsenum
* dnsrecon
* sslscan
* uniscan
* snmp-user-enum
* osscanner
* wafw00f
* odat

## To run autoenum from anywhere
```
cp ~/autoenum/autoenum.sh /usr/bin/
chmod o+x /usr/bin/autoenum.sh

autoenum.sh -h 
```
