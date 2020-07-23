#!/bin/bash

#source functions/menu/web.sh
#source functions/menu/smb.sh
#source functions/menu/dns.sh
#source functions/menu/fingerprint.sh
#source functions/menu/validate.sh
#source functions/menu/amass.sh

menu (){

WHITE='\033[01;37m'
CLEAR='\033[0m'
# https://medium.com/bugbountywriteup/fasten-your-recon-process-using-shell-scripting-359800905d2a

if [[  "$module" == "" ]];then
        cli="Autoenum($IP) > "
fi

tput bold;tput setaf 1;echo -en "$cli";tput sgr0;read arg
while true && [[ ! "$IP" == " " ]];do
                # add more color
                # add more banners (?)...grimmie want more banners :(

        mkbasedirs (){
        echo "[+] Checking for base dirs..."
        if [[ ! -d "$IP/autoenum" ]];then mkdir -p $IP/autoenum;fi
        if [[ ! -d "$IP/autoenum/loot/raw" ]];then mkdir -p $IP/autoenum/loot/raw; loot="$IP/autoenum/loot";else loot="$IP/autoenum/loot";fi
        if [[ ! -d "$loot/exploits" ]];then mkdir -p $loot/exploits;fi
        echo "[+] Done!"
        }
        case $arg in
                "")
                        menu
                        break
                        ;;
                "home")
                        cli="Autoenum($IP) > "
                        menu
                        break
                        ;;
                "commands")
                        halp_meh
                        menu
                        break
                        ;;
                "shell")
                        shell_preserve
                        menu
                        break
                        ;;
                "reset")
                        reset
                        menu
                        break
                        ;;
                "upgrade")
                        upgrade
                        menu
                        break
                        ;;
                "clear")
                        clear
                        menu
                        break
                        ;;
                "banner")
                        banner
                        menu
                        break
                        ;;
                "ping")
			if [[ "$IP" == "dev" ]];then
				echo "[-] set an IP. use set target to do this"
			else
                        	ping $IP -c 1;echo -e
			fi
			menu
                        break
                        ;;
		"udp")
			echo "[~] SCAN MODE: udp";sleep 2;echo -e
			mkbasedirs
			udp
			menu
			break
			;;
                "vuln")
                        echo "[~] SCAN MODE: vuln";sleep 2;echo -e
                        mkbasedirs
                        vuln
                        menu
                        break
                        ;;
                "aggr")
                        echo "[~] SCAN MODE: aggr";sleep 2;echo -e
                        mkbasedirs
                        aggr
                        cleanup
                        menu
                        break
                        ;;
                "reg")
                        echo "[~] SCAN MODE: reg";sleep 2;echo -e
                        mkbasedirs
                        reg
                        cleanup
                        menu
                        break
                        ;;
                "quick")
                        echo "[~] SCAN MODE: quick";sleep 2;echo -e
                        nmap -sC -sV -T4 -Pn $IP
                        menu
                        break
                        ;;
		"top 1k" | "top1k")
			echo "[~] SCAN MODE: top 1k";sleep 2;echo -e
			mkbasedirs
			top_1k
			cleanup
			menu
			break
			;;
		"top 10k" | "top10k")
			echo "[~] SCAN MODE: top 10k";sleep 2;echo -e
			mkbasedirs
			top_10k
			cleanup
			menu
			break
			;;
		"top 1k+vuln" | "top1k+vuln")
			echo "[~] SCAN MODE: top 1k+vuln";sleep 2;echo -e
			mkbasedirs
			top_1k
			vuln
			cleanup
			menu
			break
			;;
		"top 10k+vuln" | "top10k+vuln")
			echo "[~] SCAN MODE: top 10k+vuln";sleep 2;echo -e
			mkbasedirs
			top_10k
			vuln
			cleanup
			menu
			break
			;;
                "aggr+vuln")
                        echo "[~] SCAN MODE: aggr+vuln";sleep 2;echo -e
                        mkbasedirs
                        aggr
                        vuln
                        cleanup
                        menu
                        break
                        ;;
                "reg+vuln")
                        echo "[~] SCAN MODE: reg+vuln";sleep 2;echo -e
                        mkbasedirs
                        reg
                        vuln
                        cleanup
                        menu
                        break
                        ;;
                "help")
                        halp_meh_pws
                        menu
                        break
                        ;;
                "set target")
                        echo -en "Enter IP/hostname > ";read unchecked_IP
                        if [[ $unchecked_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];then
                		cwd=$(pwd);ping -c 1 $unchecked_IP | head -n2 | tail -n1 > $cwd/tmp
                		if ! grep -q "64 bytes" "tmp";then
					echo "[-] IP failed to resolve"
				else
					IP="$unchecked_IP";tput setaf 4;echo -e "[+] IP set to $IP";tput sgr0;echo -e
				fi
				rm $cwd/tmp
		        elif [[ $unchecked_IP =~ [a-z,A-Z,0-9].[a-z]$ ]] || [[ $unchecked_IP =~ [a-z].[a-z,A-Z,0-9].[a-z]$ ]];then
                		IP=$(host $unchecked_IP | head -n1 | awk '{print($4)}')
                		tput setaf 4;echo -e "$unchecked_IP resolved to $IP\n";tput sgr0
                        elif [[ $unchecked_IP == "*" ]];then
				IP="dev"
			else
                                echo "[-] Invalid IP detected."
                                echo "[-] Example: 192.168.1.5"
                        fi
                        echo "[*] IP changed to $IP"
                        menu
                        break
                        ;;
#                "use amass")
#                        echo "[*] OWASP amass set to use"
#                        OWASP_amass
#                        break
#                        ;;
#                "list modules")
                        # while base autoenum runs nmap an analysis based on services discovered, this module tatgets and deeply analyses target services while base autoenum glosses over services found
#			echo "[*] Validate"
#			echo "[*] Fingerprinting"
#			echo "[*] Web"
#			echo "[*] Samba"
#			echo "[*] DNS"
#			echo "[*] AD"
#                       menu
#                        break
#                        ;;
#                "set module")
#                        echo -en "module > ";read module
#			if [[ "$module" == "Validate" ]];then
#				module="Validate";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#				mkbasedirs
#				mkdir -p $loot/Modules/$module
#				validate_dir="$loot/Modules/$module"
#				echo "[+] Entering module: $module";sleep 1.5
#				validate
#			elif [[ "$module" == "Fingerprinting" ]];then
#				module="Fingerprinting";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                fprint_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#				fingerprint
#                        elif [[ "$module" == "Web" ]];then
#				module="Web";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                web_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                Web
#                        elif [[ "$module" == "DNS" ]];then
#				module="DNS";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                DNS_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                DNS
#                        elif [[ "$module" == "AD" ]];then
#				module="AD";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                AD_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                AD
#                        elif [[ "$module" == "Samba" ]];then
#				module="Samba";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                samba_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                Samba
#                        else
#                                echo "[-] Invalid module selected"
#                        fi
#                        menu
#                        break
#                        ;;
                "exit")
                        tput setaf 8;echo "[-] Terminating session..."
                        tput sgr0
                        sleep 1.5
			exit 1
                        ;;
                *)
                        tput setaf 8;echo "[-] Invalid input detected"
                        tput sgr0
                        menu
                        break
                        ;;
        esac
done
}
