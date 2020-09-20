#!/bin/bash

cleanup (){
        echo "[+] Cleaning up..."
        find $IP/autoenum/ -type d -empty -delete
        find $IP/autoenum/ -type f -empty -delete
        if [[ -f "installed" ]];then rm installed;fi
}

get_ip (){
        echo -e
        echo "Enter a target IP or hostname "
        tput bold;tput setaf 1; echo -en "Autoenum > ";tput sgr0;read unchecked_IP
        if [ $nr ];then
                if [[ $unchecked_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];then
                        IP="$unchecked_IP";sleep 1
                        tput setaf 4;echo -e "[+] IP set to $IP";tput sgr0;echo -e
                fi
        else
                if [[ $unchecked_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];then
                        IP="$unchecked_IP";sleep 1
                        cwd=$(pwd);ping -c 1 -W 3 $IP | head -n2 | tail -n1 > $cwd/tmp
                        if ! grep -q "64 bytes" "tmp";then
                                echo -e "[-] IP failed to resolve\n[-] Exiting..."
                                exit
                        fi
                        rm $cwd/tmp
                        tput setaf 4;echo -e "[+] IP set to $IP";tput sgr0;echo -e
                elif [[ $unchecked_IP =~ [a-z,A-Z,0-9].[a-z]$ ]] || [[ $unchecked_IP =~ [a-z].[a-z,A-Z,0-9].[a-z]$ ]];then
                        IP=$(host $unchecked_IP | head -n1 | awk '{print($4)}')
                        tput setaf 4;echo -e "$unchecked_IP resolved to $IP\n";tput sgr0
                else
                        tput setaf 8
                        echo "[-] Invalid IP or hostname detected."
                        echo -e "[-] Example:\n\t[>] 192.168.1.5\n\t[>] google.com"
                        tput sgr0
                        get_ip
                fi
        fi
}

shell_preserve (){
        echo "[+] You have entered shell mode. use done to exit"
        while true ;do
                echo -en "[+] Command > ";read cmd
                if [[ "$cmd" =~ "done" ]];then
                        $cmd  2>/dev/null;echo -e
                        break
		elif [[ "$cmd" =~ "exit" ]];then
			echo -en "[-] Exit shell mode? [y/n] > ";read opt
			if [[ "$opt" == "y" ]];then
				echo -e "[-] Exiting shell mode\n"
				break
			fi
                else
                        $cmd 2>/dev/null
                fi
        done
}

halp_meh (){
        tput smul;echo "General Commands:";tput rmul
        echo -e "[*] ping"
        echo -e "[*] help"
        echo -e "[*] banner"
        echo -e "[*] clear"
#        echo -e "[*] home"
        echo -e "[*] reset"
        echo -e "[*] commands"
        echo -e "[*] shell"
        echo -e "[*] upgrade"
        echo -e "[*] set target"
#        echo -e "[*] use [tool]"
        echo -e "[*] exit"
        echo -e
        tput smul;echo "Scan Profiles:";tput rmul
        tput bold;echo -e "[~] Main:";tput sgr0
        echo -e "[*] aggr"
        echo -e "[*] reg"
	echo -e "[*] top 1k"
	echo -e "[*] top 10k"
        echo -e "[*] aggr+vuln"
        echo -e "[*] reg+vuln"
	echo -e "[*] top 1k+vuln"
	echo -e "[*] top 10k+vuln"
	echo -e "[*] udp"
        echo -e
        tput bold;echo -e "[~] Auxiliary:";tput sgr0
        echo -e "[*] vuln"
        echo -e "[*] quick"
#        tput smul;echo "Standalone Utils:";tput rmul
#        echo -e "[*] amass"
#        echo -e
#        tput smul;echo "Module Commands:";tput rmul
#        echo -e "[*] list modules"
#        echo -e "[*] set module";
	echo -e;sleep 0.5
}

halp_meh_pws (){
        tput smul;echo "General Commands:";tput rmul
        echo "[*] ping - Verify host is up/accepting ping probes"
        echo "[*] help - displays this page"
        echo "[*] banner - display banner"
        echo "[*] clear - clears screen"
#        echo "[*] home - returns to home module"
        echo "[*] reset - run this if text is unviewable after a scan"
        echo "[*] commands - shows all avaliable commands"
        echo "[*] shell - allows you to run commands as if in a terminal"
        echo "[*] upgrade - checks to see if any dependencies require an update"
        echo "[*] set target - opens prompt to change target IP"
#        echo "[*] use [tool] - invokes use of a standalone tool"
        echo -e
        tput smul;echo "Scan Profiles:";tput rmul
        tput bold;echo "[~] Main - These scans are 'the works', enumerate further depending on services discovered ";tput sgr0
        echo "[*] aggr - scans all ports aggressively"
        echo "[*] reg - scans all ports normally, no scripts and checks only for OS"
	echo "[*] top 1k - run a number of scans on the first 1000 ports"
	echo "[*] top 10k - runs a number of scans on the first 10000 ports"
        echo "[*] aggr+vuln - aggr scan. Also fires off NSE on discovered services searching for known exploits"
        echo "[*] reg+vuln - reg scan. Also firing off NSE on discovered services searching for known exploits"
	echo "[*] top 1k+vuln - runs the top 1k scans and vuln scan"
	echo "[*] top 10k+vuln - runs the top 10k scans and vuln scan"
	echo "[*] udp - checks for udp ports"
        echo -e
        tput bold;echo "[~] Auxiliary - These scans can be run standalone, do not enumerate beyond";tput sgr0
        echo "[*] quick - scans with scripts enabled for quick script enumeration"
        echo "[*] vuln - searches for services and checks for known exploits"
        echo -e;sleep 0.5
#       tput smul;echo "Standalone Tools:";tput rmul
#       echo "[*] amass - invokes the OWASP amass tool, highly configurable"
#       echo -e
#        tput smul;echo "Module Commands:";tput rmul
#        echo "[*] list modules - prints list of availiable modules"
#        echo "[*] set module - opens prompt to move into or change modules
}
