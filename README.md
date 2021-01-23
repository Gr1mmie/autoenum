```
                 __                                      
  ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___ 
 / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \
/ /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /
\__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/ 
                                                         
```
## Summary
Autoenum is a recon tool which performs automatic enumeration of services discovered. I built this to save some time during CTFs and pen testing environments (i.e. HTB, VulnHub, OSCP) and draws a bit from a number of existing tools including AutoRecon (https://github.com/Tib3rius/AutoRecon), Auto-Recon (https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon), and nmapautomator (https://github.com/21y4d/nmapAutomator). Could also be used in a real-life pentesting engagment. Currently has only been tested in kali. If you notice a bug or have a feature request not in to-do, please submit an issue or let know some other way(discord preferred). Thanks and enjoy autoenum!  

## How it Works
Autoenum first runs 2 nmap scans in tandem, one scan looks specifically for service versions to run against searchsploit and the other is a scan dependent on the argument. Every scan profile checks for services running, the type of scan is the only difference. After the scans are finished, the services/ports open and operating systems along with script output (if avaliable) is extracted and further analyzed. If a certain service is found, Autoenum will begin enumerating by firing off a number of tools and create a dir for that service (i.e detecting http starts up nikto, wafw00f, gobuster, and others). If a dependency required is not detected, that dependency will be auto installed and checked if there is a new update everytime the tool is run. Autoenum outputs this information in 2 main sections(scan type and loot dirs) with sub directories branching off depending on what is found.

## Installation
```
git clone https://github.com/Gr1mmie/autoenum.git
chmod +x autoenum/autoenum.sh
```

## What's new

### Version 1.1
* First version, HTTP and SMB enumeration added as well as functionalized mess of code it was before 
* Aggressive scan added, included nmap-to-searchsploit scan for version exploit searching
* Added getopts for argument parsing to replace patchwork position-based conditionals

### Version 1.2
* Added help menu and logic to detect dependencies
* Fixed terminal breaking issue (kinda, open to ideas if there is anything better than clearing terminal output). 

### Version 1.3
* Fixed simultaneous scan issue so that both scans fire at the same time now and have a few tools for certain service enumerations to run in background as others stay in foreground to save time

### Version 1.4
* Added enumeration for various services including LDAP, SNMP, SMTP, oracle and FTP and banner
* Added file containing all commands run in case a command failed
* installs tools not detected and checks if all are up-to-date

### Version 1.4.1
* fixed searchsploit encoding issue where parts were being displayed as encoded when read from a text editor

### Version 2.0
* Autoenum now runs as a console tool similar to msfconsole. 

### Version 2.0.1
* persistent shell command

### Version 2.1 
* imap, mysql,redis enumeration

### Version 3.0
* Polished UI
* Cleaned up shell util errors and fixed escape keywords
* Added more scan options:
  * top 1k scan
  * top 10k scan
  * UDP scan
* Added Combination scans (vuln scan can be added onto any other scan)
* Added Auxilary scans:
  * Quick scan added
  * Vuln scan added
* Fixed update throwing errors issue
* Now supports URLs and FQDNs 
* Verifies the IP entered is a valid one
* aggr + reg scans now scan top 1k ports first
* Performs basic OS detecting using ttl
* searchsploit output is now sent to a JSON file for easy viewing
* nfs enum now attempts to mount discovered nfs shares
* Fixed http multiple ports not being detected issue

### Version 3.0.1
* Removed ports 47001 and 5985 from ports list to prevent them from being run through http enum
* added `-nr` flag when starting autoenum to set autoenum to not attempt to resolve an IP passed (this is good if a machine is blocking pings but we know its up)
  * Usage: `./autoenum -nr`

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
* oscanner
* wafw00f
* odat
* searchsploit
* rpcbind
* tput
* jq
* wpscan

## Thanks
Dievus

## Featured 
https://www.kitploit.com/2020/07/autoenum-automatic-service-enumeration.html
