#!/bin/bash

# IDEAS
# implement getopts to allow for multiple nmap profiles
# add way to enum OS, pull from OS_detection, last line after OS:
# if port shoes up as open in discovered but then doesn't show up again, -sV that port
# custon dirs depedning on IP and profile like sumrecon
IP=$1

nmap_aggr="nmap -A -T4 -p- -Pn -v $IP"
#nmap_reg="nmap -p- -T4 -Pn -v $IP"


if [ ! -x "$(command -v nmap)" ];then
	echo "[+] nmap not found. Exiting..."
	exit 1
fi

if [ ! -x "$(command -v nikto)" ];then
	echo "[+] nikto not found. Exiting..."
	exit 1
fi

if [ ! -x "$(command -v gobuster)" ];then
	echo "[+] gobuster not found. Exiting..."
	exit 1
fi

if [[ "$IP" == " " ]]; then
	echo "[-] No IP supplied..."
	exit 1
fi

if [[ ! -d "autoenum" ]];then mkdir autoenum; fi
if [[ ! -d "autoenum/aggr_scan/raw" ]];then mkdir -p autoenum/aggr_scan/raw; fi
if [[ ! -d "autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p autoenum/aggr_scan/ports_and_services; fi
if [[ ! -d "autoenum/loot/exploits" ]];then mkdir -p autoenum/loot/exploits; fi

nmap -sV $IP -oX autoenum/aggr_scan/raw/xml_out & $nmap_aggr | tee autoenum/aggr_scan/raw/full_scan;searchsploit -v --nmap autoenum/aggr_scan/raw/xml_out
cat autoenum/aggr_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> autoenum/aggr_scan/ports_and_services/services_running
cat autoenum/aggr_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> autoenum/aggr_scan/ports_and_services/OS_detection
cat autoenum/aggr_scan/raw/full_scan | grep "script results" > autoenum/aggr_scan/ports_and_services/script_output; cat autoenum/aggr_scan/raw/first_pass | grep "|" | sed '$d' >>  autoenum/aggr_scan/ports_and_services/script_output

cat autoenum/aggr_scan/ports_and_services/services_running | awk '{print($4,$5,$6,$7,$8,$9)}' | sort -u | awk 'NF' | tee autoenum/loot/services
cat autoenum/loot/services | awk '{$1=$1};1' | tr ' ' '-' | tee autoenum/loot/services
for service in $(cat autoenum/loot/services);do
	svc=$(echo $service | tr '-' ' '| tr '/' ' ')
	echo "checking $svc..."
	searchsploit "$svc" | tee "autoenum/loot/exploits/searchsploit_$svc"
	if grep -q "Exploits: No Result" "autoenum/loot/exploits/searchsploit_$svc";then rm "autoenum/loot/exploits/searchsploit_$svc";fi
#		if [[ ! "$(echo $svc wc -w)" -gt "3" ]];then rm autoenum/loot/exploits/searchsploit_$svc;fi
#		while [[ "$(echo $svc | wc -w)" -gt 3 ]]; do
#			svc=$(echo $svc | sed 's/\w*$//')
#			searchsploit $svc | tee autoenum/loot/exploits/searchsploit_$svc
#			if grep -q "Exploits: No Results" "autoenum/loot/exploits/searchsploit_$svc"; then rm autoenum/loot/exploits/searchsploit_$svc;fi
#	fi

done
rm autoenum/loot/services

cat autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "http" | egrep "8080|443|12443|81|82|8081|8082" >> autoenum/aggr_scan/raw/http_found
if [ ! -f 'autoenum/aggr_scan/raw/http_found' ]; then cat autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "http" >> autoenum/aggr_scan/raw/http_found; fi
if [ -s 'autoenum/aggr_scan/raw/http_found' ]
	then
		mkdir -p autoenum/loot/http
		mkdir -p autoenum/loot/http/dirs
		echo "[+] http enum starting..."
		if [ -s 'autoenum/loot/http/ports' ]
			then
				for port in $(cat autoenum/loot/http/ports)
					do
						echo "running nikto on port $port"
						nikto -h $IP:$port >> autoenum/loot/http/nikto_$port &
						echo "bruteforcing dirs on $IP:$port"
						gobuster dir -re -t 25 -u $IP:$port -w /usr/share/wordlists/dirb/common.txt -o autoenum/loot/http/dirs/dirs_found
					done
				rm autoenum/loot/http/ports
			else
				rm autoenum/loot/http/ports
				nikto -h $IP >> autoenum/loot/http/nikto_output &
				gobuster dir -re -t 25 -u $IP -w /usr/share/wordlists/dirb/common.txt -o autoenum/loot/http/dirs/dirs_found
		fi
		echo "[+] http enum complete!"
		rm autoenum/aggr_scan/raw/http_found
	else
		rm autoenum/aggr_scan/raw/http_found
fi

cat autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" >> autoenum/aggr_scan/raw/smb_found
if [ -s 'autoenum/aggr_scan/raw/smb_found' ]
	then
		echo "[+] Starting SMB enum..."
		mkdir -p autoenum/loot/smb
		nmap --script=smb-check-vulns.nse --script-args=unsafe=1 -p 139,445 $IP -oN autoenum/loot/smb/general_vulns
		sleep 3
		nmap --script=smb-enum-shares.nse --script-args=unsafe=1 -p 139,445 $IP -oN autoenum/loot/smb/enum_shares
		sleep 3
		nmap --script=smb-enum-users.nse --script-args=unsafe=1 -p 139,445 $IP -oN autoenum/loot/smb/enum_users
		sleep 3
		nmap --script=smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP -oN autoenum/loot/smb/eternalblue
		sleep 3
		nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP -oN autoenum/loot/smb/08-067
		rm autoenum/aggr_scan/raw/smb_found
		echo "[+] SMB enum complete!"
	else
		rm autoenum/aggr_scan/raw/smb_found
fi

find autoenum/ -type d -empty -delete
find autoenum/ -type f -empty -delete;

exit 1
