#!/bin/bash

OS_guess (){
	guess=$(ping -c 1 -W 3 $IP | grep '64' | awk '{print($6)}' | cut -d '=' -f2)
	if [[ "$guess" == 127 ]] || [[ "$guess" == 128 ]];then
		tput setaf 2;echo "[*] This machine is probably running Windows";tput sgr0
	elif [[ "$guess" == 255 ]] || [[ "$guess" == 254 ]];then
		tput setaf 2;echo "[*] This machine is probably running Cisco/Solaris/OpenBSD";tput sgr0
	elif [[ "$guess" == 63 ]] || [[ "$guess" == 64 ]];then
		tput setaf 2;echo "[*] This machine is probably running Linux";tput sgr0
	else
		echo "[-] Could not determine OS"
	fi
	sleep 1.5
}

enum_goto (){
        if [[ -s "$loot/raw/redis_found" ]];then redis_enum;fi
        if [[ -s "$loot/raw/snmp_found" ]];then snmp_enum;fi
#       if [[ -s "$loot/raw/rpc_found" ]];then rpc_enum;fi
        if [[ -s "$loot/raw/pop3_found" ]];then pop3_enum;fi
        if [[ -s "$loot/raw/imap_found" ]];then imap_enum;fi
#       if [[ -s "$loot/raw/dns_found" ]];then dns_enum;fi
        if [[ -s "$loot/raw/ftp_found" ]];then ftp_enum;fi
        if [[ -s "$loot/raw/ldap_found" ]];then ldap_enum;fi
        if [[ -s "$loot/raw/smtp_found" ]];then smtp_enum;fi
        if [[ -s "$loot/raw/oracle_found" ]];then oracle_enum;fi
        if [[ -s "$loot/raw/smb_found" ]];then smb_enum;fi
        if [[ -s "$loot/raw/http_found" ]];then http_enum;fi

        if [[ -s "$loot/raw/windows_found" ]];then windows_enum;fi
        if [[ -s "$loot/raw/linux_found" ]];then linux_enum;fi

}

reg (){
        banner
        upgrade
	OS_guess
        nmap_reg="nmap -p- -O -T4 -Pn -v $IP"
        if [[ ! -d "$IP/autoenum/reg_scan/raw" ]];then mkdir -p $IP/autoenum/reg_scan/raw; fi
        if [[ ! -d "$IP/autoenum/reg_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/reg_scan/ports_and_services; fi
        tput setaf 6;echo "Checking top 1k ports...";tput sgr0
        nmap --top-ports 1000 -sV $IP | tee -a $IP/autoenum/reg_scan/top_1k
        tput setaf 6;echo -e "Scan complete. View 1k scan at $IP/autoenum/aggr_scan/top_1k\nStarting more comprehensive scan...";tput sgr0
        nmap -sV $IP -oX $IP/autoenum/reg_scan/raw/xml_out & $nmap_reg | tee $IP/autoenum/reg_scan/raw/full_scan;searchsploit -j --nmap $IP/autoenum/reg_scan/raw/xml_out >> $loot/exploits/searchsploit_nmap
        searchsploit --nmap $IP/autoenum/reg_scan/raw/xml_out
        cat $loot/exploits/searchsploit_nmap | jq >> $loot/exploits/searchsploit_nmap.json
        rm $loot/exploits/searchsploit_nmap

        cat $IP/autoenum/reg_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/reg_scan/ports_and_services/services_running
        cat $IP/autoenum/reg_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/reg_scan/ports_and_services/OS_detection
        cat $IP/autoenum/reg_scan/raw/full_scan | sed -n '/PORT/,/exact/p' | sed '$d' >>  $IP/autoenum/reg_scan/ports_and_services/script_output

        cat $IP/autoenum/reg_scan/ports_and_services/services_running | grep "http" | sort -u >> $loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f 1;done >  $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "smb" > $loot/raw/smb_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "snmp" > $loot/raw/snmp_found
#       cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "imap" > $loot/raw/imap_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "oracle" > $loot/raw/oracle_found
#       cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

aggr (){
        banner
        upgrade
	OS_guess
        nmap_aggr="nmap -n -A -T4 -p- --max-retries 1 -Pn -v $IP"
        if [[ ! -d "$IP/autoenum/aggr_scan/raw" ]];then mkdir -p $IP/autoenum/aggr_scan/raw; fi
        if [[ ! -d "$IP/autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/aggr_scan/ports_and_services; fi
	tput setaf 6;echo "Checking top 1k ports...";tput sgr0
	nmap --top-ports 1000 -sV $IP | tee -a $IP/autoenum/aggr_scan/top_1k
        tput setaf 6;echo -e "Scan complete. View 1k scan at $IP/autoenum/aggr_scan/top_1k\nStarting more comprehensive scan...";tput sgr0
        nmap -sV $IP -oX $IP/autoenum/aggr_scan/raw/xml_out & $nmap_aggr | tee $IP/autoenum/aggr_scan/raw/full_scan;searchsploit -j --nmap $IP/autoenum/aggr_scan/raw/xml_out >> $loot/exploits/aggr_searchsploit_nmap
        searchsploit --nmap $IP/autoenum/aggr_scan/raw/xml_out
        cat $loot/exploits/aggr_searchsploit_nmap | jq >> $loot/exploits/aggr_searchsploit_nmap.json;rm $loot/exploits/aggr_searchsploit_nmap

        cat $IP/autoenum/aggr_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/aggr_scan/ports_and_services/services_running
        cat $IP/autoenum/aggr_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/aggr_scan/ports_and_services/OS_detection
        cat $IP/autoenum/aggr_scan/raw/full_scan | sed -n '/PORT/,/exact/p' | sed '$d' >>  $IP/autoenum/aggr_scan/ports_and_services/script_output

        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f 1 ;done > $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" > $loot/raw/smb_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "snmp" > $loot/raw/snmp_found
#       cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "imap" > $loot/raw/imap_found
#       cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

top_1k (){
	banner
	upgrade
	OS_guess
        if [[ ! -d "$IP/autoenum/top_1k/raw" ]];then mkdir -p $IP/autoenum/top_1k/raw; fi
        if [[ ! -d "$IP/autoenum/top_1k/ports_and_services" ]];then  mkdir -p $IP/autoenum/top_1k/ports_and_services; fi
	t1k="$IP/autoenum/top_1k"
	nmap --top-ports 1000 -sV -Pn $IP | tee -a $t1k/ports_and_services/services & nmap --top-ports 1000 -sC -Pn $IP >> $t1k/ports_and_services/scripts
	nmap --top-ports 1000 -sV $IP -oX $t1k/raw/xml_out &
	wait
	searchsploit -j --nmap $t1k/raw/xml_out >> $loot/exploits/top_1k_searchsploit_nmap;searchsploit --nmap $t1k/raw/xml_out
        cat $loot/exploits/top_1k_searchsploit_nmap | jq >> $loot/exploits/top_1k_searchsploit_nmap.json

        cat $t1k/ports_and_services/services | grep "open" |grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f 1;done >  $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $t1k/ports_and_services/services | sort -u | grep "smb" > $loot/raw/smb_found
        cat $t1k/ports_and_services/services | sort -u | grep "snmp" > $loot/raw/snmp_found
#       cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
        cat $t1k/ports_and_services/services | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $t1k/ports_and_services/services | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $t1k/ports_and_services/services | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $t1k/ports_and_services/services | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $t1k/ports_and_services/services | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $t1k/ports_and_services/services | sort -u | grep "imap" > $loot/raw/imap_found
#       cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found
        cat $t1k/ports_and_services/services | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

top_10k (){
	banner
	upgrade
	OS_guess
        if [[ ! -d "$IP/autoenum/top_10k/raw" ]];then mkdir -p $IP/autoenum/top_10k/raw; fi
        if [[ ! -d "$IP/autoenum/top_10k/ports_and_services" ]];then  mkdir -p $IP/autoenum/top_10k/ports_and_services; fi
	t10k="$IP/autoenum/top_10k"
	nmap --top-ports 10000 -sV -Pn --max-retries 1 $IP | tee -a $t10k/raw/services & nmap --top-ports 10000 --max-retries 1 -sC -Pn $IP >> $t10k/raw/scripts
	nmap --top-ports 10000 ---max-retries 1 sV $IP -oX $t10k/raw/xml_out &
	wait
	searchsploit -j --nmap $t10k/raw/xml_out >> $loot/exploits/top_10k_searchsploit_nmap;searchsploit --nmap $t10k/raw/xml_out
        cat $loot/exploits/top_10k_searchsploit_nmap | jq >> $loot/exploits/top_10k_searchsploit_nmap.json
	cat $t10k/raw/services | grep 'open' >> $t10k/ports_and_services/services

        cat $t10k/ports_and_services/services | grep "http" | sort -u >> $loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f1;done > $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $t10k/ports_and_services/services | sort -u | grep "smb" > $loot/raw/smb_found
        cat $t10k/ports_and_services/services | sort -u | grep "snmp" > $loot/raw/snmp_found
        cat $t10k/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
        cat $t10k/ports_and_services/services | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $t10k/ports_and_services/services | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $t10k/ports_and_services/services | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $t10k/ports_and_services/services | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $t10k/ports_and_services/services | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $t10k/ports_and_services/services | sort -u | grep "imap" > $loot/raw/imap_found
        cat $t10k/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found
        cat $t10k/ports_and_services/services | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

udp (){
	banner
	upgrade
	OS_guess
        if [[ ! -d "$IP/autoenum/udp/raw" ]];then mkdir -p $IP/autoenum/udp/raw; fi
        if [[ ! -d "$IP/autoenum/udp/ports_and_services" ]];then  mkdir -p $IP/autoenum/udp/ports_and_services; fi
        udp="$IP/autoenum/udp"
	nmap -sU --max-retries 1 --open $IP | tee -a $udp/scan

}

vuln (){
        mkdir -p $loot/exploits/vulns
        vulns="$loot/exploits/vulns"
        cwd=$(pwd)

        if [[ ! -d "/usr/share/nmap/scripts/vulscan" ]];then
                cd
                git clone https://github.com/scipag/vulscan scipag_vulscan
                ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
                cd $cwd
        fi

        nmap -sV --script=vulscan/vulscan.nse $IP | tee -a $vulns/vulscan
        nmap -Pn --script vuln $IP | tee -a $vulns/vuln
}

