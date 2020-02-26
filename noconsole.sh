#!/bin/bash

halp_meh (){
	echo "[*] Usage: ./autoenum [profile] <IP>"
	echo "[*] Example: ./autoenum -a 127.0.0.1"
	echo "[*] Profiles:"
	echo "		[>] -a runs aggresive scan. scans all ports aggresively"
	echo "		[>] -r runs regular scan. scans all ports normally, no scripts and checks only for OS"
}

banner (){
#	echo "									"
        echo '                   --                                       '
        echo '    ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___  '
        echo '   / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \ '
        echo '  / /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / / '
        echo '  \__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/  '
	echo "							           "
	echo " Author: Grimmie						   "
	echo " Version: 1.4						   "
	echo "									"
#	echo "##############################################################"
        echo "                                                          "
	sleep 1.5
}


IP=$2

# install if not installed, update if not up-to-date (only if root)
# check if root, if so, install

if [ ! -x "$(command -v nmap)" ];then
	echo "[+] nmap not detected...Installing"
	sudo apt-get install nmap -y > installing;rm installing
fi

if [ ! -x "$(command -v nikto)" ];then
	echo "[+] nikto not detected. Installing..."
	sudo apt-get install nikto -y > installing;rm installing
fi

if [ ! -x "$(command -v gobuster)" ];then
	echo "[+] gobuster not detected. Installing..."
	sudo apt-get install gobuster -y > installing;rm installing
fi

if [ ! -x "$(command -v whatweb)" ];then
       echo "[+] whatweb not detected. installing..."
	sudo apt-get install whatweb -y > installing;rm installing
fi

if [ ! -x "$(command -v onesixtyone)" ];then
        echo "[+] onesixtyone not detected. Installing..."
        sudo apt-get install onesixtyone -y > installing;rm installing
fi

if [ ! -x "$(command -v rpcbind)" ];then
	echo "rpcbind not detected. Installing..."
	sudo apt-get install rpcbind -y > installing;rm installing

fi

if [ ! -x "$(command -v snmp-check)" ];then
        echo "[+] snmp-check not detected. Installing..."
        sudo apt-get install snmp-check -y > installing;rm installing
fi

if [ ! -x "$(command -v snmpwalk)" ];then
        echo "[+] snmpwalk not detected. Installing..."
        sudo apt-get install snmpwalk -y > installing;rm installing
fi

if [ ! -x "$(command -v fierce)" ];then
        echo "[+] fierce not detected. Installing..."
        sudo apt-get install fierce -y > installing;rm installing
fi

if [ ! -x "$(command -v dnsrecon)" ];then
        echo "[+] dnsrecon not detected. Installing..."
        sudo apt-get installl dnsrecon -y > installing;rm installing
fi

if [ ! -x "$(command -v dnsenum)" ];then
        echo "[+] dnsenum not detected. Installing..."
        sudo apt-get install dnsenum -y > installing;rm installing
fi

if [ ! -x "$(command -v oscanner)" ];then
        echo "[+] oscanner not detected. Installing..."
        sudo apt-get install oscanner -y > installing;rm installing
fi

if [ ! -x "$(command -v wafw00f)" ];then
        echo "[+] wafw00f not detected. Installing..."
	sudo apt-get install wafw00f -y > installing;rm installing
fi

if [ ! -x "$(command -v odat)" ];then
        echo "[+] odat not detected. installing..."
	sudo apt-get install odat -y > installing;rm installing
fi

upgrade (){
	echo "[*] Checking if anything requires updates, this may take a few minutes...."
	apt-get install nmap >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install nmap -y >> installing; rm installed installing;fi &
	apt-get install nikto >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install nikto -y >> installing; rm installed installing;fi &
	apt-get install wafw00f >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install wafw00f -y >> installing; rm installed installing;fi &
	apt-get install gobuster >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install gobuster -y >> installing; rm installed installing;fi &
	apt-get install odat >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install odat -y >> installing; rm installed installing;fi &
	apt-get install oscanner >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install oscanner -y >> installing; rm installed installing;fi &
	#snmp-check,snmpwalk
	apt-get install dnsenum >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install dnsenum -y >> installing; rm installed installing;fi &
	apt-get install dnsrecon >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install dnsrecon -y >> installing; rm installed installing;fi &
	apt-get install fierce >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install fierce -y >> installing; rm installed installing;fi &
	apt-get install onesixtyone >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install onesixtyone -y >> installing; rm installed installing;fi &
	apt-get install whatweb >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install whatweb -y >> installing; rm installed installing;fi &
	apt-get install rpcbind >> installed;if ! grep -q "already the newest version" "installed";then sudo apt-get install rpcbind -y >> installing; rm installed installing;fi &
	wait
}


if [[ "$IP" == " " ]];then
	echo "[-] No IP supplied..."
	echo "[*] ./autoenum -h for more info"
	exit 1
fi

if [[ ! "$1" == " " ]]; then
	if [[ ! -d "$IP/autoenum" ]];then mkdir -p $IP/autoenum;fi
	if [[ ! -d "$IP/autoenum/loot/raw" ]];then
		mkdir -p $IP/autoenum/loot/raw
		loot="$IP/autoenum/loot"
	fi
	if [[ ! -d "$IP/autoenum/loot/exploits" ]];then mkdir -p $IP/autoenum/loot/exploits;fi
else
	halp_meh
fi

reg (){
	banner
	upgrade
	nmap_reg="nmap -p- -O -T4 -Pn -v $IP"

	if [[ ! -d "$IP/autoenum/reg_scan/raw" ]];then mkdir -p $IP/autoenum/reg_scan/raw; fi
        if [[ ! -d "$IP/autoenum/reg_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/reg_scan/ports_and_services; fi

        nmap -sV $IP -oX $IP/autoenum/reg_scan/raw/xml_out & $nmap_aggr | tee $IP/autoenum/reg_scan/raw/full_scan;searchsploit -j --nmap $IP/autoenum/reg_scan/raw/xml_out | tee -a  $loot/exploits/searchsploit_nmap
	cat $loot/exploits/searchsploit_nmap | jq >> $loot/exploits/searchsploit_nmap.json
	rm $loot/exploits/searchsploit_nmap

        cat $IP/autoenum/reg_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/reg_scan/ports_and_services/services_running
        cat $IP/autoenum/reg_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/reg_scan/ports_and_services/OS_detection
#        cat $IP/autoenum/reg_scan/raw/full_scan | grep "script results" > $IP/autoenum/reg_scan/ports_and_services/script_output;cat $IP/autoenum/reg_scan/raw/full_scan | grep "|" | sed '$d' >>  $IP/autoenum/reg_scan/ports_and_services/script_output

#       cat $IP/autoenum/reg_scan/ports_and_services/services_running | awk '{print($4,$5,$6,$7,$8,$9)}' | sort -u | awk 'NF' >> $IP/autoenum/loot/services

        cat $IP/autoenum/reg_scan/ports_and_services/services_running | grep "http" | egrep "80|8080|443|12443|81|82|8081|8082" >> $IP/autoenum/loot/raw/http_found.tmp
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
        cat $IP/autoenum/loot/raw/http_found.tmp | sort -u >> $IP/autoenum/loot/raw/http_found;
        rm $IP/autoenum/loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found | tr ' ' '-');do echo $line | awk '(!/^80/ && !/^8080/ && !/^443/ && !/^12443/ && !/^81/ && !/^82/)' >  $loot/raw/ports;done
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "smb" > $loot/raw/smb_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "snmp" > $loot/raw/snmp_found
#       cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "smtp" > $loot/raw/smtp_found
	cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "imap" > $loot/raw/imap_found
	cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found

        if [[ -s "$loot/raw/snmp_found" ]];then snmp_enum;fi
        if [[ -s "$loot/raw/rpc_found" ]];then rpc_enum;fi
        if [[ -s "$loot/raw/pop3_found" ]];then pop3_enum;fi
        if [[ -s "$loot/raw/imap_found" ]];then imap_enum;fi
#       if [[ -s "$loot/raw/dns_found" ]];then dns_enum;fi
        if [[ -s "$loot/raw/ftp_found" ]];then ftp_enum;fi
        if [[ -s "$loot/raw/ldap_found" ]];then ldap_enum;fi
        if [[ -s "$loot/raw/smtp_found" ]];then smtp_enum;fi
        if [[ -s "$loot/raw/oracle_found" ]];then oracle_enum;fi
	if [[ -s "$loot/raw/pop3_found" ]];then pop3_enum;fi
	if [[ -s "$loot/raw/imap_found" ]];then imap_enum;fi
        if [[ -s "$loot/raw/smb_found" ]];then smb_enum;fi
        if [[ -s "$loot/raw/http_found" ]] || [ -s "$loot/raw/ports" ];then http_enum;fi

#        if [[ -s "$loot/raw/windows_found" ]];then windows_enum;fi
#        if [[ -s "$loot/raw/linux_found" ]];then linux_enum;fi

}

aggr (){
	banner
	upgrade
	nmap_aggr="nmap -A -T4 -p- -Pn -v $IP"

	if [[ ! -d "$IP/autoenum/aggr_scan/raw" ]];then mkdir -p $IP/autoenum/aggr_scan/raw; fi
	if [[ ! -d "$IP/autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/aggr_scan/ports_and_services; fi

	nmap -sV $IP -oX $IP/autoenum/aggr_scan/raw/xml_out & $nmap_aggr | tee $IP/autoenum/aggr_scan/raw/full_scan;searchsploit -j --nmap $IP/autoenum/aggr_scan/raw/xml_out | tee -a $loot/exploits/searchsploit_nmap
	cat $loot/exploits/searchsploit_nmap | jq >> $loot/exploits/searchsploit_nmap.json
        rm $loot/exploits/searchsploit_nmap

	cat $IP/autoenum/aggr_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/aggr_scan/ports_and_services/services_running
	cat $IP/autoenum/aggr_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/aggr_scan/ports_and_services/OS_detection
	cat $IP/autoenum/aggr_scan/raw/full_scan | grep "script results" > $IP/autoenum/aggr_scan/ports_and_services/script_output;cat $IP/autoenum/aggr_scan/raw/full_scan | grep "|" | sed '$d' >>  $IP/autoenum/aggr_scan/ports_and_services/script_output

#	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | awk '{print($4,$5,$6,$7,$8,$9)}' | sort -u | awk 'NF' >> $IP/autoenum/loot/services

	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | grep "http" | egrep "80|8080|443|12443|81|82|8081|8082" >> $IP/autoenum/loot/raw/http_found.tmp
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
	cat $IP/autoenum/loot/raw/http_found.tmp | sort -u >> $IP/autoenum/loot/raw/http_found;
	rm $IP/autoenum/loot/raw/http_found.tmp
	for line in $(cat $loot/raw/http_found | tr ' ' '-');do echo $line | awk '(!/^80/ && !/^8080/ && !/^443/ && !/^12443/ && !/^81/ && !/^82/)' >  $loot/raw/ports;done
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" > $loot/raw/smb_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "snmp" > $loot/raw/snmp_found
#	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "ftp" > $loot/raw/ftp_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "ldap" > $loot/raw/ldap_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smtp" > $loot/raw/smtp_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "oracle" > $loot/raw/oracle_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "pop3" > $loot/raw/pop3_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "imap" > $loot/raw/imap_found
	cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found

	if [[ -s "$loot/raw/snmp_found" ]];then snmp_enum;fi
	if [[ -s "$loot/raw/rpc_found" ]];then rpc_enum;fi
	if [[ -s "$loot/raw/pop3_found" ]];then pop3_enum;fi
	if [[ -s "$loot/raw/imap_found" ]];then imap_enum;fi
#	if [[ -s "$loot/raw/dns_found" ]];then dns_enum;fi
	if [[ -s "$loot/raw/ftp_found" ]];then ftp_enum;fi
	if [[ -s "$loot/raw/ldap_found" ]];then ldap_enum;fi
	if [[ -s "$loot/raw/smtp_found" ]];then smtp_enum;fi
	if [[ -s "$loot/raw/oracle_found" ]];then oracle_enum;fi
	if [[ -s "$loot/raw/smb_found" ]];then smb_enum;fi
	if [[ -s "$loot/raw/http_found" ]] || [[ -s "$loot/raw/ports" ]];then http_enum;fi

#	if [[ -s "$loot/raw/windows_found" ]];then windows_enum;fi
#	if [[ -s "$loot/raw/linux_found" ]];then linux_enum;fi

}

snmp_enum (){
	mkdir $loot/snmp
	onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP | tee -a $loot/snmp/snmpenum
	snmp-check -c public -v 1 -d $IP | tee -a $loot/snmp/snmpcheck
	if grep -q "SNMP request timeout" "$loot/snmp/snmpcheck";then
		rm $loot/snmp/snmpcheck
		snmpwalk -c public -v2c $IP | tee -a $loot/snmp/uderstuff
		echo "snmpwalk -c public -v2c $IP" >> $loot/snmp/cmds_run &
		if grep -q "timeout" "$loot/snmp/uderstuff";then rm $loot/snmp/uderstuff;else mv $loot/snmp/uderstuff $loot/snmp/snmpenum;fi
	else
		mv $loot/snmp/snmpcheck $loot/snmp/snmpenum
	fi
	echo "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP" >> $loot/snmp/cmds_run &
	echo "snmp-check -c public $IP" >> $loot/snmp/cmds_run &
	wait

	rm $IP/autoenum/loot/raw/snmp_found
}

rpc_enum (){
	mkdir $loot/rpc
	rpcbind -p $IP | tee -a $loot/rpc/versions
	rm $loot/raw/rpc_found
}

pop3_enum (){
	mkdir $loot/pop3
	nmap -sV --script pop3-brute $IP | tee -a $loot/pop3/brute
	echo "telnet $IP 110" >> $loot/pop3/manual_cmds
	rm $loot/raw/pop3_found
}

imap_enum (){
	echo "[+] Work in progress"
}

ldap_enum (){
	mkdir $loot/ldap
	nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP | tee -a $loot/ldap/ldap_scripts
	#ldapsearch -x -h $rhost -s base namingcontexts | tee -a $loot/ldap/ldapsearch &
	echo "nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP" >> $loot/ldap/cmds_run &
	wait

	rm $loot/raw/ldap_found
}

dns_enum (){
	# mainly for pentesting use, not neccesary rn for oscp. retest later when adding to this
	#fierce -dns $IP
	#dnsenum --enum $IP
	#dnsrecon -d $IP
	#gobuster -dns $IP
	echo " "
}

ftp_enum (){
	mkdir -p $loot/ftp
	echo "[+] Starting FTP enum..."
	cat $loot/raw/ftp_found | awk '{print($1)}' | cut -d '/' -f 1 > $loot/ftp/port_list
	for port in $(cat $loot/ftp/port_list);do
		nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP | tee -a $loot/ftp/ftp_scripts
	done
	echo "nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP " >> $loot/ftp/cmds_run &
	wait

	rm $loot/ftp/port_list
	rm $loot/raw/ftp_found
	echo "[+] FTP enum complete"
}

smtp_enum (){
	mkdir $loot/smtp
	cat $loot/raw/snmp_found | awk '{print($1)}' | cut -d '/' -f 1 > $loot/smtp/port_list
	for port in $(cat $loot/smtp/port_list);do
		smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port | tee -a $loot/smtp/users
	done
	if grep -q "0 results" "$loot/smtp/users";then rm $loot/smtp/users;fi
	echo "nc -nvv $IP $port" >> $loot/smtp/maunal_cmds
	echo "telnet $IP $port" >> $loot/smpt/manual_cmds
 	echo "smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port" >> $loot/smtp/cmds_run &
	wait

	rm $loot/smtp/port_list
	rm $loot/raw/smtp_found
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
	rm $loot/raw/oracle_found
}

http_enum (){
	mkdir -p $IP/autoenum/loot/http
	mkdir -p $IP/autoenum/loot/http/dirs
	mkdir -p $IP/autoenum/loot/http/whatweb
	mkdir -p $IP/autoenum/loot/http/wafw00f
	mkdir -p $IP/autoenum/loot/http/ssl
	mkdir -p $IP/autoenum/loot/http/nikto
	mkdir -p $IP/autoenum/loot/http/uniscan
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
			curl $IP:$port/robots.txt >> $IP/autoenum/loot/http/robots &
			if ! grep -q "disallow" "autoenum/loot/http/robots";then rm $IP/autoenum/loot/http/robots;fi
			echo "[+] checking for plugin data"
			whatweb -v -a 3 http://$IP:$port | tee -a $IP/autoenum/loot/http/whatweb/plugins_$port
			echo "[+] waf hunting..."
			wafw00f http://$IP:$port | tee -a $IP/autoenum/loot/http/wafw00f/wafs_$port
		done
		rm $IP/autoenum/loot/http/ports
	else
		uniscan -u http://$IP -qweds | tee -a $IP/autoenum/loot/http/uniscan/out
		echo "[+] checking ssl for possible holes"
		sslscan $IP:80 | tee -a $IP/autoenum/loot/http/sslinfo
		echo "[+] firing up nikto"
		nikto -h $IP >> $IP/autoenum/loot/http/nikto/nikto_output &
		echo "[+] bruteforcing dirs on $IP"
		gobuster dir -re -t 25 -u $IP -w /usr/share/wordlists/dirb/common.txt -o $IP/autoenum/loot/http/dirs/dirs_found
		echo "[+] checking for robot.txt files"
		curl $IP/robots.txt >> $IP/autoenum/loot/http/robots &
		if ! grep -q "disallow" "autoenum/loot/http/robots";then rm $IP/autoenum/loot/http/robots;fi
		echo "[+] checking for plugin data"
		whatweb -v -a 3 http://$IP | tee -a $IP/autoenum/loot/http/whatweb/plugins
		echo "[+] checking for wafs"
		wafw00f http://$IP | tee -a  $IP/autoenum/loot/http/wafw00f/wafs
		if grep -q "No WAF detected by the generic detection" "$IP/autenum/loot/http/wafw00f/wafs";then rm $IP/autoenum/loot/http/wafw00f/wafs;fi
	fi
		touch $loot/http/cmds_run
		echo "uniscan -u http://$IP -qweds" >> $loot/http/cmds_run &
		echo "sslscan $IP:80 " >> $loot/http/cmds_run &
		echo "nikto -h $IP" >> $loot/http/cmds_run &
		echo "gobuster dir -re -t 25 -u $IP -w /usr/share/wordlists/dirb/common.txt" >> $loot/http/cmds_run &
		echo "curl $IP/robots.txt" >> $loot/http/cmds_run &
		echo "whatweb -v -a 3 http://$IP" >> $loot/http/cmds_run &
		echo "wafw00f http://$IP" >> $loot/http/cmds_run &
		wait

		echo "[+] http enum complete!"
		rm $IP/autoenum/loot/raw/http_found
}

smb_enum (){
	echo "[+] Starting SMB enum..."
	mkdir -p $loot/smb
	mkdir -p $loot/smb/shares
	# checks for eternal blue and other common smb vulns
	nmap --script smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a $loot/smb/eternalblue
	if ! grep -q "smb-vuln-ms17-010:" "auotenum/loot/smb/eternalblue"; then rm $loot/smb/eternalblue;fi
	nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP | tee -a $loot/smb/08-067
	if ! grep -q "smb-vuln-ms08-067:" "autoenum/loot/smb/08-067";then rm $loot/smb/08-067;fi
	nmap --script smb-vuln* -p 139,445 $IP | tee -a $loot/smb/gen_vulns
	#shares n' stuff
	nmap --script smb-enum-shares -p 139,445 $IP | tee -a $loot/smb/shares/nmap_shares
	smbmap -H $IP -R | tee -a $loot/smb/shares/smbmap_out
	smbclient -N -L \\\\$IP | tee -a $loot/smb/shares/smbclient_out

	if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out";then smbclient -N -H \\\\\\$IP | tee -a $loot/smb/shares/smbclient_out;fi
	if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out";then smbclient -N -H \\$IP | tee -a $loot/smb/shares/smbclient_out;fi
	if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out";then rm $loot/smb/shares/smbclient_out; echo "smbclient could not be auotmatically run, rerun smbclient -N -H [IP] manauly" >> $loot/smb/notes;fi
	if grep -q "Error NT_STATUS_UNSUCCESSFUL" "$loot/smb/shares/smbclient_out";then rm $loot/smb/shares/smbclient;fi

	if [[ -s "$loot/smb/shares/smbclient_out" ]];then echo "smb shares open to null login, use rpcclient -U '' -N [ip] to run rpc commands, use smbmap -u null -p '' -H $IP -R to verify this" >> $loot/smb/notes;fi

	find ~ -path '*/$IP/autoenum/loot/smb/*' -type f > $loot/smb/files
	for file in $(cat $loot/smb/files);do
		if grep -q "QUITTING!" "$file" || grep -q "ERROR: Script execution failed" "$file" || grep "segmentation fault" "$file";then rm $file;fi
	done

	touch $loot/smb/cmds_run
	echo "nmap --script smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP " >> $loot/smb/cmds_run &
	echo "nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP" >> $loot/smb/cmds_run &
	echo "nmap --script smb-vuln* -p 139,445 $IP" >> $loot/smb/cmds_run &
	echo "nmap --script smb-enum-shares -p 139,445 $IP" >> $loot/smb/cmds_run &
	echo "smbmap -H $IP -R " >> $loot/smb/cmds_run &
	echo "smbclient -N -L \\\\$IP " >> $loot/smb/cmds_run &
	wait

	rm $loot/smb/files
	rm $loot/raw/smb_found
	echo "[+] SMB enum complete!"
}

linux_enum (){
	echo "[-] Work in Progress"
}

windows_enum (){
	echo "[-] Work in Progress"
}



cleanup (){
	echo "[+] Cleaning up..."
	find $IP/autoenum/ -type d -empty -delete
	find $IP/autoenum/ -type f -empty -delete
	rm installed
}

while getopts "hba:r:" opt;do
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
		b )
		  banner
		  exit 1
		  ;;

	esac
done

shift $((OPTIND -1))
