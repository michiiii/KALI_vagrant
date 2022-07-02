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
alias pbpaste='xclip -selection clipboard -o'

## Unzip & untar
echo "unzip - uses 7z to unzip a file - unzip <filename.zip>"
alias unzip="7z x "
alias untar="tar -xvf "

echo -e "${YELLOW}${BOLD}\n========================${NC}"
echo -e "${YELLOW}${BOLD}[ - DOCKER - ]${NC}"
echo -e "${YELLOW}${BOLD}========================${NC}"

alias dcls = "sudo docker container ls -a"
alias dils = "sudo docker images"

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

echo "nginxhere - spawns nginx http server in current dir - nginxhere <HTTP-PORT> <HTTPS-PORT>"
function nginxhere() {
        PORT_HTTP=$1
        PORT_HTTPS=$2
        RED='\033[0;31m'
        NC='\033[0m' # No Color
        if [ $# -eq 2 ];then
                FILE="/opt/ssl/server.crt"
                if test -f "$FILE"; then
                    echo "$FILE Certificate exists ... continuing ..."
                    sudo docker run -d --rm -it -p "$PORT_HTTP:80" -p "$PORT_HTTPS:443" --name "nginx" -v "/opt/ssl/server.key:/etc/nginx/ssl/server.key" -v "/opt/ssl/server.crt:/etc/nginx/ssl/server.crt" -v "${PWD}:/srv/data" miguel1337/nginxhere:latest    
                else
                    echo "$FILE Certificate does not exist exists ... generating cert ..."
                    sudo mkdir /opt/ssl/ 
                    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /opt/ssl/server.key -out /opt/ssl/server.crt -subj '/C=US/ST=WA/L=Redmond/O=Microsoft Corporation/OU=Microsoft Corporation/CN=www.microsoft.com'
                    sudo docker run -d --rm -it -p "$PORT_HTTP:80" -p "$PORT_HTTPS:443" --name "nginx" -v "/opt/ssl/server.key:/etc/nginx/ssl/server.key" -v "/opt/ssl/server.crt:/etc/nginx/ssl/server.crt" -v "${PWD}:/srv/data" miguel1337/nginxhere:latest
                fi
                
                echo "You can access the nginxwebserver via the following url: "
                echo "http://0.0.0.0:$PORT_HTTP"
                echo "https://0.0.0.0:$PORT_HTTPS"
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
alias nmapfastscan="sudo docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -Pn -n --top-ports 1000 -vvvv --open --max-retries 3 --max-rtt-timeout 900ms --min-hostgroup 254 --min-rate 30000 --defeat-rst-ratelimit --host-timeout 1m "

echo "nmapfulltcpscan - runs NMAP scanner; all TCP ports; specify <IP's>"
alias nmapfulltcpscan="sudo docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -n -Pn -p- -vvvv --open --min-rate 20000 --defeat-rst-ratelimit --host-timeout 5m -oA /tmp/nmap_fulltcp --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl "

echo "nmapservicescan - runs NMAP scanner; specific TCP ports; specify <IP's> and -p <PORTS>"
alias nmapservicescan="sudo docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -n -sV -vvvv --open -sC --script-timeout 15m -O -Pn -oA /tmp/nmap_servicescan "

echo "testssl-docker - testssl docker version - testssl-docker"
alias testssl-docker='sudo docker run --rm -ti -v "${PWD}:/data" drwetter/testssl.sh -s -f -p -S -P -h -U --ip one --htmlfile /data/ --logfile /data/ --jsonfile-pretty /data/ --csvfile /data/ --warnings=batch'

echo "cme - CrackMapExec docker edition - cme <args>"
alias cme='sudo docker run --rm -it --entrypoint=/usr/local/bin/cme --name crackmapexec-run -v "${PWD}/CrackMapExec-data:/root/.cme" byt3bl33d3r/crackmapexec'

echo "getports - returns ports of a nmap scan - getports <nmapfile.nmap>"
function getports() {
        # extracts all ports from an nmap scan file as one-line
        # to be used as -sS -Pn -sV -sC -O -p <oneliner>
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
                curl -Lks $URL | tac | sed "s#\\\/#\/#g" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | sed -r "s/^src['\"]?[=:]['\"]//g" | awk -v url=$URL '{if(length($1)) if($1 ~/^http/) print $1; else if($1 ~/^\/\//) print "https:"$1; else print url"/"$1}' | sort -fu | xargs -I '%' sh -c "echo \"\n##### %\";wget --no-check-certificate --quiet \"%\";curl -Lks \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"('#####.*)|(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\" | sort -fu" | tr -d "'\""
        else
                echo -e "${RED}Please enter an URL as argument ... jsEndpoints <url to js>${NC}"
        fi
   
}
# https://gist.github.com/gwen001/0b15714d964d99c740a7e8998bd483df

echo -e "${YELLOW}${BOLD}\n==============================${NC}"
echo -e "${YELLOW}${BOLD}[ - ALIASES - ]${NC}"
echo -e "${YELLOW}${BOLD}==============================${NC}"
echo "updatealiases - update .bash_aliases with newest github version"
alias updatealiases='(curl -k -q -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases) && source ~/.bash_aliases && echo "Updated aliases..."'

echo -e "${YELLOW}${BOLD}\n==============================\n${NC}"