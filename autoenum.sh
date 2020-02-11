#!/bin/bash

#nmap_reg="nmap -p- -T4 -Pn -v $IP"

halp_meh (){
	echo "[*] Usage: ./autoenum [profile] <IP>"
	echo "[*] Example: ./autoenum -a 127.0.0.1"
	echo "[*] Profiles:"
	echo "		[>] -a runs aggresive scan"
	echo "		[>] -r runs regular scan"
}

IP=$2

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

if [[ "$IP" == " " ]];then
	echo "[-] No IP supplied..."
	echo "[*] ./autoenum -h for more info"
	exit 1
fi

if [[ "$1" == " " ]] || [[ "$1" != "-h" ]]; then
	if [[ ! -d "autoenum" ]];then mkdir autoenum;fi
	if [[ ! -d "autoenum/loot/raw" ]];then mkdir -p autoenum/loot/raw;fi
	if [[ ! -d "autoenum/loot/exploits" ]];then mkdir -p autoenum/loot/exploits;fi
else
	halp_meh
fi

aggr (){
	nmap_aggr="nmap -A -T4 -p- -Pn -v $IP"

	if [[ ! -d "autoenum/aggr_scan/raw" ]];then mkdir -p autoenum/aggr_scan/raw; fi
	if [[ ! -d "autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p autoenum/aggr_scan/ports_and_services; fi

	nmap -sV $IP -oX autoenum/aggr_scan/raw/xml_out & $nmap_aggr | tee autoenum/aggr_scan/raw/full_scan;searchsploit -v --nmap autoenum/aggr_scan/raw/xml_out | tee autoenum/loot/exploits/searchsploit_nmap
	cat autoenum/aggr_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> autoenum/aggr_scan/ports_and_services/services_running
	cat autoenum/aggr_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> autoenum/aggr_scan/ports_and_services/OS_detection
	cat autoenum/aggr_scan/raw/full_scan | grep "script results" > autoenum/aggr_scan/ports_and_services/script_output;cat autoenum/aggr_scan/raw/full_scan | grep "|" | sed '$d' >>  autoenum/aggr_scan/ports_and_services/script_output
	cat autoenum/aggr_scan/ports_and_services/services_running | awk '{print($4,$5,$6,$7,$8,$9)}' | sort -u | awk 'NF' >> autoenum/loot/services

	cat autoenum/aggr_scan/ports_and_services/services_running | grep "http" | egrep "80|8080|443|12443|81|82|8081|8082" >> autoenum/loot/raw/http_found.tmp
	cat autoenum/aggr_scan/ports_and_services/services_running | grep "http" | sort -u >> autoenum/loot/raw/http_found.tmp
	cat autoenum/loot/raw/http_found.tmp | sort -u >> autoenum/loot/raw/http_found

	for line in $(cat autoenum/loot/raw/http_found | tr ' ' '-');do echo $line | awk '(!/^80/ && !/^8080/ && !/^443/ && !/^12443/ && !/^81/ && !/^82/)' | tee  autoenum/loot/raw/ports;done

	cat autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" >> autoenum/loot/raw/smb_found

	ssploit

	if [ -s 'autoenum/loot/raw/smb_found' ];then smb_enum;fi

	if [ -s 'autoenum/loot/raw/http_found' ] || [ -s 'autoenum/loot/raw/ports' ];then http_enum;fi

}

ssploit (){
	# searchsploit "smart pass"
	cat autoenum/loot/services | awk '{$1=$1};1' | tr ' ' '-' | tee autoenum/loot/services
	for service in $(cat autoenum/loot/services);do
		svc=$(echo $service | tr '-' ' '| tr '/' ' ')
		echo "checking $svc..."
		searchsploit "$svc" | tee "autoenum/loot/exploits/searchsploit_$svc"
		if grep -q "Exploits: No Result" "autoenum/loot/exploits/searchsploit_$svc";then rm "autoenum/loot/exploits/searchsploit_$svc";fi
#			if [[ ! "$(echo $svc wc -w)" -gt "3" ]];then rm autoenum/loot/exploits/searchsploit_$svc;fi
#			while [[ "$(echo $svc | wc -w)" -gt 3 ]]; do
#				svc=$(echo $svc | sed 's/\w*$//')
#				searchsploit $svc | tee autoenum/loot/exploits/searchsploit_$svc
#				if grep -q "Exploits: No Results" "autoenum/loot/exploits/searchsploit_$svc"; then rm autoenum/loot/exploits/searchsploit_$svc;fi
#			done
#		fi
#
	done
	rm autoenum/loot/services
}

http_enum (){
	mkdir  autoenum/loot/http
	mkdir  autoenum/loot/http/dirs
	echo "[+] http enum starting..."
	if [ -s 'autoenum/loot/raw/ports' ]; then mv autoenum/loot/raw/ports autoenum/loot/http/ports;fi
	if [ -s 'autoenum/loot/http/ports' ];then
		# curl robots.txt and other interesting universal files
		echo "firing up nikto"
		nikto -h $IP >> autoenum/loot/http/nikto_output &
		for port in $(cat autoenum/loot/http/ports);do
			echo "bruteforcing dirs on $IP:$port"
			gobuster dir -re -t 25 -u $IP:$port -w /usr/share/wordlists/dirb/common.txt -o autoenum/loot/http/dirs/dirs_found
		done
		rm autoenum/loot/http/ports
	else
		nikto -h $IP >> autoenum/loot/http/nikto_output &
		gobuster dir -re -t 25 -u $IP -w /usr/share/wordlists/dirb/common.txt -o autoenum/loot/http/dirs/dirs_found
	fi
		echo "[+] http enum complete!"
		rm autoenum/loot/raw/http_found
}

smb_enum (){
	echo "[+] Starting SMB enum..."
	mkdir -p autoenum/loot/smb
	mkdir -p autoenum/loot/smb/shares
	# general smb vulns
	nmap --script smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a  autoenum/loot/smb/eternalblue
	nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP | tee -a  autoenum/loot/smb/08-067
	nmap --script smb-vuln* -p 139,445 $IP >> autoenum/loot/smb/gen_vulns
	#shares n' stuff
	nmap --script smb-enum-shares -p 139,445 10.11.1.2 $IP -oN autoenum/loot/smb/shares/nmap_shares
	smbmap -H $IP -R | tee -a autoenum/loot/smb/shares/smbmap
	smbclient -N -L \\\\$IP | tee -a autoenum/loot/smb/shares/smbclient

	if grep -q "Not enough '\' characters in service" "autoenum/loot/smb/shares/smbclient";then smbclient -N -H \\\\\\$IP | tee autoenum/loot/smb/shares/shares/smbclient;fi
	if grep -q "Not enough '\' characters in service" "autoenum/loot/smb/shares/smbclient";then smbclient -N -H \\$IP | tee autoenum/loot/smb/shares/smbclient;fi
	if grep -q "Not enough '\' characters in service" "autoenum/loot/smb/shares/smbclient";then rm autoenum/loot/smb/shares/smbclient; echo "smbclient could not be auotmatically run, rerun smbclient -N -H [IP] manauly" >>  autoenum/loot/smb/notes;fi
	if grep -q "(Error NT_STATUS_UNSUCCESSFUL)" "autoenum/loot/smb/shares/smbclient";then rm autoenum/loot/smb/shares/smbclient;fi

	if [ -s "autoenum/loot/smb/shares/smbmap" ] || [ -s "autoenum/loot/smb/shares/smbclient" ];then echo "smb shares open to null login, use rpcclient -U "" -N [ip] to run rpc commands" | tee -a autoenum/loot/smb/notes;fi

	find ~ -path '*/autoenum/loot/smb/*' -type f > autoenum/loot/smb/files
	for file in $(cat autoenum/loot/smb/files);do
		if grep -q "QUITTING!" "$file" || ! grep -q "Host script results:" "$file" || grep -q "ERROR: Script execution failed" "$file" || grep "segmentation fault" "$file";then rm $file;fi
	done

	rm autoenum/loot/raw/smb_found
	echo "[+] SMB enum complete!"
}

cleanup (){
	find autoenum/ -type d -empty -delete
	find autoenum/ -type f -empty -delete
}

while getopts "a:hr:" opt; do
	case ${opt} in
		a )
		  aggr
		  cleanup
		  reset
		  exit 1
		  ;;
		r )
		  reg
		  cleanup
		  reset
		  exit 1
	          ;;
		h )
		  halp_meh
		  exit 1
		  ;;

	esac
done

shift $((OPTIND -1))
