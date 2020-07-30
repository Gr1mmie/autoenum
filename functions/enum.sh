#!/bin/bash

redis_enum (){
        mkdir $loot/redis
	tput setaf 2;echo "[+] Starting redis enum";tput sgr0
        nmap --script redis-info -sV -p 6379 $IP | tee -a $loot/redis/redis_info
        echo "msf> use auxiliary/scanner/redis/redis_server" >> $loot/redis/manual_cmds
}

snmp_enum (){
        mkdir $loot/snmp
	tput setaf 2;echo "[+] Starting snmp enum";tput sgr0
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP | tee -a $loot/snmp/snmpenum
#       create algo to check which version of snmp is runnign or pull it off a banner grab
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
	tput setaf 2;echo "[+] Starting rpc enum";tput sgr0
        port=$(cat $loot/raw/rpc_found | grep "rpc" | awk '{print($1)}' | cut -d '/' -f 1)
        nmap -sV -p $port --script=rpcinfo >> $loot/rpc/ports
        if grep -q "" "$loot/rpc/ports";then rm $loot/rpc/ports;fi
        rpcbind -p $IP | tee -a $loot/rpc/versions
        if grep -q "nfs" "$loot/rpc/ports";then nfs_enum;fi
        rm $loot/raw/rpc_found
}

nfs_enum (){
        mkdir $loot/nfs
	tput setaf 2;echo "[+] Starting nfs enum";tput sgr0
        nmap -p 111 --script nfs* $IP | tee $loot/nfs/scripts
        # add chunk to automount if share is found
        share=$(cat $loot/nfs/scripts | grep "|_ " -m 1 | awk '{print($2)}')
        if grep -q "mfs-showmount" "$loot/nfs/scripts";then
                mkdir $loots/nfs/mount
                # pull share location and assign it to share var
                mount -o nolock $IP:$share $loot/nfs/mount
        fi
}

pop3_enum (){
        mkdir $loot/pop3
	tput setaf 2;echo "[+] Starting pop3 enum";tput sgr0
        nmap -sV --script pop3-brute $IP | tee -a $loot/pop3/brute
        echo "telnet $IP 110" >> $loot/pop3/manual_cmds
        rm $loot/raw/pop3_found
}

imap_enum (){
        echo "[+] Work in progress"
}

ldap_enum (){
        mkdir $loot/ldap
	tput setaf 2;echo "[+] Starting ldap enum";tput sgr0
        nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP | tee -a $loot/ldap/ldap_scripts
        #ldapsearch -x -h $rhost -s base namingcontexts | tee -a $loot/ldap/ldapsearch &
        echo "nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP" >> $loot/ldap/cmds_run &
        wait
        rm $loot/raw/ldap_found
}

dns_enum (){
        mkdir $loot/dns
        # mainly for pentesting use, not neccesary rn for oscp. retest later when adding to this
        #host $IP >> $loot/dns/host_out
        #host -t mx $IP >> $loot/dns/host_out
        #host -t txt $IP >> $loot/dns/host_out
        #host -t ns $IP >> $loot/dns/host_out
        #host -t ptr $IP >> $loot/dns/host_out
        #host -t cname $IP >> $loot/dns/host_out
        #host -t a $IP >> $loot/dns/host_out
        #for host in <list of subs>;do host -l <host> <dns server addr>;done
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
	echo "[+] Starting SNMP enum..."
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
	echo "[+] Starting Oracle enum..."
        #swap out port with port(s) found running oracle
        nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse | tee -a $loot/oracle/nmapstuff
        oscanner -v -s $IP -P 1521 | tee -a $loot/oracle/
        echo "[+] Running ODAT..."
        odat tnscmd -s $rhost --version --status --ping 2>/dev/null | tee -a $loot/oracle/odat_tnscmd
        odat sidguesser -s $rhost 2>/dev/null | tee -a $loot/oracle/odat_enum
        rm $loot/raw/oracle_found
}

http_enum (){
        mkdir -p $IP/autoenum/loot/http
        echo "[+] http enum starting..."
	pct=$(cat $loot/raw/http_found | wc -l)
	if [[ $pct -gt 1 ]];then
		echo "[+] Multiple HTTP ports detected"
                for port in $(cat $loot/raw/http_found);do
			mkdir $loot/http/$port
                        echo "[+] Firing up nikto on port $port"
                        nikto -ask=no -h $IP:$port -T 123b | tee -a  $loot/http/$port/nitko
	                echo "[+] checking ssl for possible holes on port $port"
			sslscan --show-certificate $IP:$port | tee -a $loot/http/$port/sslinfo &
			echo "[+] Curling interesting files on port $port"
			curl -sSiK $IP:$port/index.html | tee -a $loot/http/$port/landingpage &
			curl -sSik $IP:$port/robots.txt | tee -a $loot/http/$port/robots.txt &
			echo -e "\n[+] Pulling headers/plugin info with whatweb on port $port"
			whatweb -a3 $IP:$port 2>/dev/null | tee -a $loot/http/$port/whatweb &
			wait
                        echo "[+] bruteforcing dirs on $IP:$port"
                        gobuster dir -re -t 65 -u http://$IP:$port -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o $loot/http/$port/dirs_found -k
#			if IIS detected
#			echo "[*] IIS detected"
#                        echo "[+] enumerating dav..."
#                        mkdir -p $loot/dav
#                        davtest -url http://$IP:$port | tee -a $loot/dav/dav_enum_$port
#			if wordpress detected
#			echo -e "[*] WordPress detected\nRunning wpscan"
#			run wpscan | tee -a $loot/http/wpscan_$port
                done
        elif [[ $pct == 1 ]];then
		port=$(cat $loot/raw/http_found)
                echo "[+] firing up nikto"
                nikto -ask=no -h $IP:$port >> $loot/http/nikto_out &
		#echo "[+] Running unican in background"
                #uniscan -u http://$IP -bqweds >> $loot/http/uniscan
                echo "[+] checking ssl for possible holes"
                sslscan --show-certificate $IP:$port | tee -a $loot/http/sslinfo
		echo "[+] Pulling headers/plugin info with whatweb"
		whatweb -a3 $IP:$port 2>/dev/null | tee -a $loot/http/whatweb
                echo "[+] Curling interesting files"
                curl -sSiK $IP:$port/index.html | tee -a $loot/http/landingpage &
                curl -sSik $IP:$port/robots.txt | tee -a $loot/http/robots.txt &
		wait
                echo "[+] bruteforcing dirs on $IP"
                gobuster dir -re -t 65 -u $IP:$port -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o $loot/http/dirs_found -k
#		if IIS detected
#                echo "[+] enumerating dav..."
#                davtest -url http://$IP | tee -a $loot/http/dav_enum
#                       if wordpress detected
#                       echo -e "[*] WordPress detected\nRunning wpscan"
#                       run wpscan | tee -a $loot/http/wpscan_$port

        fi
                touch $loot/http/cmds_run
                echo "uniscan -u http://$IP -qweds" >> $loot/http/cmds_run &
                echo "sslscan --show-certificate $IP:80 " >> $loot/http/cmds_run &
                echo "nikto -h $IP" >> $loot/http/cmds_run &
                echo "gobuster dir -re -t 45 -u $IP -w /usr/share/wordlists/dirb/common.txt" >> $loot/http/cmds_run &
                echo "curl -sSiK $IP" >> $loot/http/cmds_run &
                echo "curl -sSiK $IP/robots.txt" >> $loot/http/cmds_run &
                echo "whatweb -v -a 3 $IP" >> $loot/http/cmds_run &
#                echo "wafw00f http://$IP" >> $loot/http/cmds_run &
                wait
                echo "[+] http enum complete!"
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
        #get exact snmp version
        echo "[-] Work in Progress"
}

windows_enum (){
        # get exact snmp version
        # pull entire MIB into sections
        echo "[-] Work in Progress"
}

