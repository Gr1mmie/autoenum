#!/bin/bash
dir=$(dirname $(readlink -f $0))

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
        sudo apt install snmpcheck -y > installing;rm installing
fi

if [ ! -x "$(command -v snmpwalk)" ];then
        echo "[+] snmpwalk not detected. Installing..."
        sudo apt install snmp -y > installing;rm installing
fi

if [ ! -x "$(command -v snmp sipvicious)" ];then
        echo "[+] sipvicious not detected. Installing..."
        sudo apt install snmp sipvicious wkhtmltopdf -y > installing;rm installing
fi

if [ ! -x "$(command -v fierce)" ];then
        echo "[+] fierce not detected. Installing..."
        sudo apt-get install fierce -y > installing;rm installing
fi

if [ ! -x "$(command -v dnsrecon)" ];then
        echo "[+] dnsrecon not detected. Installing..."
        sudo apt installl dnsrecon -y > installing;rm installing
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

if [ ! -x "$(command -v jq)" ];then
        echo "[+] jq not detected. installing..."
        sudo apt-get install jq -y > installing;rm installing
fi

if [ ! -x "$(command -v tput)" ];then
        echo "[+] tput not detected. installing..."
        sudo apt-get install tput -y > installing;rm installing
fi

source $dir/functions/banner.sh
source $dir/functions/upgrade.sh
source $dir/functions/scans.sh
source $dir/functions/enum.sh
source $dir/functions/help_general.sh
source $dir/functions/menu.sh


if [[ $1 == '-nr' ]];then nr=1;fi
clear
banner
if [ $nr ];then tput setaf 2;echo -en "\n[*] autoenum set to noresolve mode";tput sgr0;sleep 0.5;fi
get_ip
halp_meh
menu

