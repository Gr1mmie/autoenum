```
                 __                                      
  ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___ 
 / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \
/ /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /
\__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/ 
                                                         
```
## Summary
Autoenum is a recon tool which performs automatic enumeration of services discovered. I built this to save some time during CTFs and pen testing environments (i.e. HTB, VulnHub, OSCP). Could also be used in a real-life pentesting engagment. Currently has only been tested in kali. If you notice a bug or have a feature request not in to-do, please submit an issue. Thanks and enjoy autoenum!  

## Dependencies
Your OS may or may not have some installed by default. Not to worry, autoenum recognizes tools not installed and install them for you, even updating if they aren't up-to-date!

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
