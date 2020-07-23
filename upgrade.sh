#!/bin/bash

upgrade (){
        echo "[*] Checking if anything requires updates, this may take a few minutes...."
	arr=('nmap' 'nikto' 'wafw00f' 'odat' 'oscanner' 'dnsenum' 'dnsrecon' 'fierce' 'onesixtyone' 'whatweb' 'rpcbind' 'gem')
	for tool in $arr[@];do
		sudo apt-get install $tool -y 2&>/dev/null &
	done
		gem install wpscan 2&>/dev/null &
	wait
        echo "[*] Done!"
}
