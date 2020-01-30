#!/bin/bash

IP=$1

nmap_aggr="nmap -A -T4 -p- -Pn -v $IP"
nmap_reg="nmap -p- -T4 -Pn -v $IP"

# add conditional to choose which scan type, set aggresive to default.

if [ ! -x "$(command -v nmap)" ]
	then
		echo "[+] nmap not found. Exiting..."
		exit 1
fi

if [ ! -x "$(command -v nikto)" ]
	then
		echo "[+] nikto not found. Exiting..."
		exit 1
fi

if [ ! -x "$(command -v gobuster)" ]
	then
		echo "[+] gobuster not found. Exiting..."
		exit 1
fi
# if aggresive (default)
if [[ ! -d "autoenum" ]];then mkdir autoenum; fi
if [[ ! -d "autoenum/aggr_scan/raw" ]];then mkdir -p autoenum/aggr_scan/raw; fi
if [[ ! -d "autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p autoenum/aggr_scan/ports_and_services; fi
if [[ ! -d "autoenum/aggr_scan/exploits" ]];then mkdir -p autoenum/aggr_scan/exploits; fi
$nmap_aggr | tee -a autoenum/aggr_scan/raw/first_pass
cat autoenum/aggr_scan/raw/first_pass | grep -i "discovered" >> autoenum/aggr_scan/ports_and_services/ports_discovered
cat autoenum/aggr_scan/raw/first_pass | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> autoenum/aggr_scan/ports_and_services/services_running
cat autoenum/aggr_scan/raw/first_pass | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> autoenum/aggr_scan/ports_and_services/OS_detection
cat autoenum/aggr_scan/raw/first_pass | grep "script results" > autoenum/aggr_scan/ports_and_services/script_output; cat autoenum/aggr_scan/raw/first_pass | grep "|" | sed '$d' >>  autoenum/aggr_scan/ports_and_services/script_output
cat autoenum/aggr_scan/ports_and_services/services_running | awk '{print($4,$5,$6,$7)}' | awk 'NF' >> autoenum/loot/services

$nmap_aggr -oX autoenum/aggr_scan/raw/nmap_out.xml
searchsploit -v --nmap -w autoenum/aggr_scan/raw/nmap_out.xml | tee -a autoenum/aggr_scan/exploits/searchsploit_nmap_first_pass

# searchsploit smart search. need to come up with a generic way to pull entire service names, also want to make it so that if nothing is found with full string, remove trailing word and rerun
#cat autoenum/aggr_scan/ports_and_services/services_running | awk '{print($5,$6,$7,$8)}' | sort -u | awk 'NF' | tee autoenum/loot/services
#cat autoenum/loot/services | awk '{$1=$1};1' | tr ' ' '-' | tee autoenum/loot/services
#for service in $(cat autoenum/loot/services);do svc=$(echo $service | tr '-' ' ');echo "checking $svc...";sleep 3; searchsploit $svc;done
find autoenum/ -type -d -empty -delete

cat autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "http" | egrep "80|8080|443|12443|81|82|8081|8082" >> autoenum/aggr_scan/raw/http_found
if [ -s 'autoenum/aggr_scan/raw/http_found' ]
	then
		mkdir -p autoenum/loot/http
		cat autoenum/aggr_scan/raw/http_found | cut -d '/' -f 1 >> autoenum/loot/http/ports
		if [ -s 'autoenum/loot/http/ports' ]
			then
				for port in $(cat autoenum/loot/http/ports)
					do
						nikto -h $IP:$port >> autoenum/loot/http/nikto_$port
						dirb http://$IP:$port >> autoenum/loot/http/dirs_$port
						rm autoenum/loot/http/ports
					done
			else
				rm autoenum/loot/http/ports
				nikto -h $IP >> autoenum/loot/http/nikto_output
				dirb http://$IP >> autoenum/loot/http/dirs
		fi
		rm autoenum/aggr_scan/raw/http_found
	else
		rm autoenum/aggr_scan/raw/http_found
fi

cat autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" >> autoenum/aggr_scan/raw/smb_found
if [ -s 'autoenum/aggr_scan/raw/smb_found' ]
	then
		mkdir -p autoenum/loot/smb
		nmap --script=smb-check-vulns.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a autoenum/loot/smb/general_vulns
		nmap --script=smb-enum-shares.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a autoenum/loot/smb/enum_shares
		nmap --script=smb-enum-users.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a autoenum/loot/smb/enum_users
		nmap --script=smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a autoenum/loot/smb/eternalblue
		rm autoenum/aggr_scan/raw/smb_found
	else
		rm autoenum/aggr_scan/raw/smb_found
fi

# IDEAS
# implement getopts to allow for multiple nmap profiles
