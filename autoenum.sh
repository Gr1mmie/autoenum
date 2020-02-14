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
	if [[ ! -d "$IP/autoenum" ]];then mkdir -p $IP/autoenum;fi
	if [[ ! -d "$IP/autoenum/loot/raw" ]];then
		mkdir -p $IP/autoenum/loot/raw
		loot="$IP/autoenum/loot"
	fi
	if [[ ! -d "$IP/autoenum/loot/exploits" ]];then mkdir -p $IP/autoenum/loot/exploits;fi
else
	halp_meh
fi

aggr (){
	nmap_aggr="nmap -A -T4 -p- -Pn -v $IP"

	if [[ ! -d "$IP/autoenum/aggr_scan/raw" ]];then mkdir -p $IP/autoenum/aggr_scan/raw; fi
	if [[ ! -d "$IP/autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/aggr_scan/ports_and_services; fi

	nmap -sV $IP -oX autoenum/aggr_scan/raw/xml_out & $nmap_aggr | tee $IP/autoenum/aggr_scan/raw/full_scan;searchsploit -v --nmap $IP/autoenum/aggr_scan/raw/xml_out | tee $IP/autoenum/loot/exploits/searchsploit_nmap
	cat $IP/autoenum/aggr_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/aggr_scan/ports_and_services/services_running
	cat $IP/autoenum/aggr_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/aggr_scan/ports_and_services/OS_detection
	cat $IP/autoenum/aggr_scan/raw/full_scan | grep "script results" > $IP/autoenum/aggr_scan/ports_and_services/script_output;cat $IP/autoenum/aggr_scan/raw/full_scan | grep "|" | sed '$d' >>  $IP/autoenum/aggr_scan/ports_and_services/script_output

	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | awk '{print($4,$5,$6,$7,$8,$9)}' | sort -u | awk 'NF' >> $IP/autoenum/loot/services

	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | grep "http" | egrep "80|8080|443|12443|81|82|8081|8082" >> $IP/autoenum/loot/raw/http_found.tmp
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
	cat $IP/autoenum/loot/raw/http_found.tmp | sort -u >> $IP/autoenum/loot/raw/http_found;
	rm $IP/autoenum/loot/raw/http_found.tmp
	for line in $(cat $loot/raw/http_found | tr ' ' '-');do echo $line | awk '(!/^80/ && !/^8080/ && !/^443/ && !/^12443/ && !/^81/ && !/^82/)' | tee $loot/raw/ports;done
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" >> $loot/raw/smb_found
#	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "snmp" | sort -u >> $IP/autoenum/loot/raw/snmp_found
#	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "dns" | sort -u >> $IP/autoenum/loot/raw/dns_found

#	set enum funcs with nmap first
	if [ -s '$loot/raw/smb_found' ];then smb_enum;fi
	if [ -s '$loot/raw/http_found' ] || [ -s 'autoenum/loot/raw/ports' ];then http_enum;fi
	if [ -s '$loot/raw/snmp_found' ];then snmp_enum;fi
	if [ -s '$loot/raw/dns_found' ];then dns_enum;fi
	if [ -s '$loot/raw/ftp_found' ];then ftp_enum;fi
	if [ -s '$loot/raw/ldap_found' ];then ldap_enum;fi
	if [ -s '$loot/raw/smtp_found' ];then smtp_enum;fi
	if [ -s '$loot/raw/oracle_found' ];then oracle_enum;fi

	if [ -s '$loot/raw/windows_found' ];then windows_enum;fi
	if [ -s '$loot/raw/linux_found' ];then linux_enum;fi
}

snmp_enum (){
	mkdir $loot/snmp
	onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP | tee -a $loot/snmp/pwshelpmenamethis
	snmp-check -c public -v 1 -d $IP | tee -a $loot/snmp/sumstuffrn
	if grep -q "SNMP request timeout" "$loot/snmp/sumstuffrn";then
		rm $loot/snmp.sumstuffrn
		snmpwalk -c public -v2c $IP | tee -a $loot/snmp/uderstuff
		if grep -q "timeout" "$loot/snmp/uderstuff"; rm $loot/snmp/uderstuff
	fi
}

ldap_enum (){
	echo "[-] Work in Progress"
}

dns_enum (){
	echo "[-] Work in Progress"
}

ftp_enum (){
	mkdir -p $loot/ftp
	echo "[+] Starting FTP enum..."
#	nmap -sV -Pn -p [insert ftp port here] --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP | tee -a  $loot/ftp/out
	echo "[+] FTP enum complete!"
}

smtp_enum (){
	mkdir $loot/smtp
#	write cmd into notes
	smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP | tee -a $loot/smtp/users
	if grep -q "0 results" "$loot/smtp/users"; rm $loot/smtp/users;fi
}

oracle_enum (){
	mkdir $loot/oracle
	#swap out port with port(s) found running oracle
	nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse | tee -a $loot/oracle/nmapstuff
	oscanner -v -s $IP -P 1521 | tee -a $loot/oracle/idk
	# add odat
	echo "[+] Running ODAT enum..."
	./odat.py tnscmd -s $rhost -p 1521 --ping | tee -a  $loot/oracle/odat_enum
        ./odat.py tnscmd -s $rhost -p 1521 --version | tee -a $loot/oracle/odat_enum
        ./odat.py tnscmd -s $rhost -p 1521 --status | tee -a $loot/oracle/odat_enum
        ./odat.py sidguesser -s $rhost -p 1521 | tee -a $loot/oracle/odat_enum
}

http_enum (){
	mkdir  -p $IP/autoenum/loot/http
	mkdir  -p $IP/autoenum/loot/http/dirs
	mkdir -p $IP/autonenum/loot/http/whatweb
	mkdir -p $IP/autoenum/loot/http/wafw00f
	echo "[+] http enum starting..."
	if [ -s 'autoenum/loot/raw/ports' ]; then mv $IP/autoenum/loot/raw/ports autoenum/loot/http/ports;rm $IP/autoenum/loot/raw/ports;fi
	if [ -s 'autoenum/loot/http/ports' ];then
		# curl robots.txt and other interesting universal files, add sslscan
		for port in $(cat $IP/autoenum/loot/http/ports);do
			echo "[+] checking ssl for possible holes"
			sslscan $IP:$port | tee -a $IP/autoenum/loot/http/sslscan_$port
			echo "[+] bruteforcing dirs on $IP:$port"
			gobuster dir -re -t 25 -u $IP:$port -w /usr/share/wordlists/dirb/common.txt -o $IP/autoenum/loot/http/dirs/dirs_found
			echo "[+] firing up nikto"
			nikto -h $IP:$port -ssl >> $IP/autoenum/loot/http/nikto_$port &
			if [ ! grep -q "no webserver found" "autoenum/loot/http/nikto_$port" ];then
				nikto -h $IP:$port >> $IP/autoenum/loot/http/nikto_$port &
			fi
			echo "[+] checking for robots.txt files"
			curl $IP:$port/robots.txt >> $IP/autoenum/loot/http/robots
			if ! grep -q "disallow" "autoenum/loot/http/robots";then rm $IP/autoenum/loot/http/robots;fi
			echo "[+] checking for plugin data"
			whatweb -v -a 3 http://$IP:$port | tee -a $IP/autoenum/loot/http/whatweb/plugins_$port
			echo "[+] waf hunting..."
			wafw00f http://$IP:$port | tee -a $IP/autoenum/loot/http/wafw00f/wafs_$port
		done
		rm $IP/autoenum/loot/http/ports
	else
		uniscan -u http://$IP -qweds | tee -a $IP/autoenum/loot/http/uniscan_out &
		echo "[+] checking ssl for possible holes"
		sslscan $IP:80 | tee -a $IP/autoenum/loot/http/sslinfo
		echo "[+] firing up nikto"
		nikto -h $IP >> $IP/autoenum/loot/http/nikto_output &
		echo "[+] bruteforcing dirs on $IP"
		gobuster dir -re -t 25 -u $IP -w /usr/share/wordlists/dirb/common.txt -o $IP/autoenum/loot/http/dirs/dirs_found
		echo "[+] checking for robot.txt files"
		curl $IP/robots.txt >> $IP/autoenum/loot/http/robots
		if ! grep -q "disallow" "autoenum/loot/http/robots";then rm $IP/autoenum/loot/http/robots;fi
		echo "[+] checking for plugin data"
		whatweb -v -a 3 http://$IP | tee -a $IP/autoenum/loot/http/whatweb/plugins
		echo "[+] checking for wafs"
		wafw00f http://$IP | tee -a  $IP/autoenum/loot/http/wafw00fwafs
		if grep -q "No WAF detected by the generic detection" "$IP/autenum/loot/http/wafw00f/wafs";then rm $IP/autoenum/loot/http/wafw00f/wafs;fi
	fi
		echo "[+] http enum complete!"
		rm $IP/autoenum/loot/raw/http_found
}

smb_enum (){
	echo "[+] Starting SMB enum..."
	mkdir -p $IP/autoenum/loot/smb
	mkdir -p $IP/autoenum/loot/smb/shares
	# checks for eternal blue and other common smb vulns
	nmap --script smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a $IP/autoenum/loot/smb/eternalblue
	if ! grep -q "smb-vuln-ms17-010:" "auotenum/loot/smb/eternalblue"; then rm $IP/autoenum/loot/smb/eternalblue;fi
	nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP | $IP/tee -a autoenum/loot/smb/08-067
	if ! grep -q "smb-vuln-ms08-067:" "autoenum/loot/smb/08-067";then rm $IP/autoenum/loot/smb/08-067;fi
	nmap --script smb-vuln* -p 139,445 $IP | tee -a $IP/autoenum/loot/smb/gen_vulns
	#shares n' stuff
	nmap --script smb-enum-shares -p 139,445 $IP | tee -a $IP/autoenum/loot/smb/shares/nmap_shares
	smbmap -H $IP -R | tee -a $IP/autoenum/loot/smb/shares/smbmap_out
	smbclient -N -L \\\\$IP | tee -a $IP/autoenum/loot/smb/shares/smbclient_out

	if grep -q "Not enough '\' characters in service" "$IP/autoenum/loot/smb/shares/smbclient_out";then smbclient -N -H \\\\\\$IP | tee -a $IP/autoenum/loot/smb/shares/smbclient_out;fi
	if grep -q "Not enough '\' characters in service" "$IP/autoenum/loot/smb/shares/smbclient_out";then smbclient -N -H \\$IP | tee -a $IP/autoenum/loot/smb/shares/smbclient_out;fi
	if grep -q "Not enough '\' characters in service" "$IP/autoenum/loot/smb/shares/smbclient_out";then rm $IP/autoenum/loot/smb/shares/smbclient_out; echo "smbclient could not be auotmatically run, rerun smbclient -N -H [IP] manauly" >> $IP/autoenum/loot/smb/notes;fi
	if grep -q "(Error NT_STATUS_UNSUCCESSFUL)" "$IP/autoenum/loot/smb/shares/smbclient_out";then rm $IP/autoenum/loot/smb/shares/smbclient;fi

	if [ -s "$IP/autoenum/loot/smb/shares/smbclient_out" ];then echo "smb shares open to null login, use rpcclient -U "" -N [ip] to run rpc commands, use smbmap -u null -p "" -H $IP -R to verify this" >> $IP/autoenum/loot/smb/notes;fi

	find ~ -path '*/$IP/autoenum/loot/smb/*' -type f > $IP/autoenum/loot/smb/files
	for file in $(cat $IP/autoenum/loot/smb/files);do
		if grep -q "QUITTING!" "$file" || grep -q "ERROR: Script execution failed" "$file" || grep "segmentation fault" "$file";then rm $file;fi
	done

	rm $IP/autoenum/loot/smb/files
	rm $IP/autoenum/loot/raw/smb_found
	echo "[+] SMB enum complete!"
}

linux_enum (){
	echo "[-] Work in Progress"
}

windows_enum (){
	echo "[-] Work in Progress"
}



cleanup (){
	find $IP/autoenum/ -type d -empty -delete
	find $IP/autoenum/ -type f -empty -delete
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
