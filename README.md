```
                 __                                      
  ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___ 
 / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \
/ /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /
\__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/ 
                                                         
```
## Summary
An all-in-one recon tool I wrote up for OSCP. Currently has only been tested in kali. If you notice a bug or have a feature request not in to-do, please submit an issue. Thanks and enjoy autorecon! 

## Dependencies
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

autoenum.sh
```
