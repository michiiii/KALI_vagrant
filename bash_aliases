
# CUSTOM ALIASES

# Nice directory listings
alias ll="ls -l"
alias la="ls -la"
command -v lsd &> /dev/null && alias ls='lsd --group-dirs first -l'

command -v htop &> /dev/null && alias top='htop'

alias mirror='wget -mkEpnp -e robots=off'
alias unblock_dir='sudo chmod -R 755'
alias block_dir='sudo chmod -R 700'
alias updog="sudo python -m updog "

alias pbcopy='xclip -selection clipboard'
alias pbpaste='xclip -selection clipboard -o'

## External IP Address
alias exip="curl https://ipinfo.io/ip"

## Unzip & untar
alias unzip="7z x "
alias untar="tar -xvf "

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

## List open ports
alias ports="sudo netstat -tulanp"

## Get header
alias header="curl -I"

## Get external IP address
alias exip="curl -s http://ipinfo.io/ip"

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

### Network Services
alias listen="netstat -antp | grep LISTEN"

## aircrack-ng
alias aircrack-ng="aircrack-ng -z"

## airodump-ng 
alias airodump-ng="airodump-ng --manufacturer --wps --uptime"

## ssh
alias ssh-start="systemctl restart ssh"
alias ssh-stop="systemctl stop ssh"

## samba
alias smb-start="systemctl restart smbd nmbd"
alias smb-stop="systemctl stop smbd nmbd"

## rdesktop
alias rdesktop="rdesktop -z -P -g 90% -r disk:local=\"/tmp/\""

## www
alias wwwroot="cd /var/www/html/"

## smb
alias smb="cd /var/samba/"
#alias smbroot="cd /var/samba/"

## wordlist
alias wordlists="cd /usr/share/wordlists/"

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

echo "work - cd straight into the projects dir"
alias work="cd /opt/projects/"







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


echo "dockershellhere - spawns dockershell for a container and includes the current directory"
function dockershellhere() {
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/${dirname} -w /${dirname} "$@"
}

echo "dockershellhere - spawns dockershell for a container and includes the current directory - dockershellhere <containername>"
function dockershellshhere() {
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/sh -v `pwd`:/${dirname} -w /${dirname} "$@"
}

echo "nginxhere - spawns nginx http server in current dir"
alias nginxhere='sudo docker run --rm -it -p 80:80 -p 443:443 -v "${PWD}:/srv/data" rflathers/nginxserve'

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

echo "dockershell - spawns dockershell for a container in it's current working directory"
alias dockershell="sudo docker run --rm -i -t --entrypoint=/bin/bash"

echo "dockershellsh - spawns dockershell for a container in it's current working directory"
alias dockershellsh="sudo docker run --rm -i -t --entrypoint=/bin/sh"

alias cme="sudo docker run --rm -it byt3bl33d3r/crackmapexec"
alias impacket="sudo docker run --rm -it rflathers/impacket"







echo "exip - returns external ip address"
echo "cme - crackmapexec docker"

echo "testssl-docker - testssl docker version"
alias testssl-docker='docker run --rm -ti -v "${PWD}:/data" drwetter/testssl.sh -s -f -p -S -P -h -U --ip one --htmlfile /data/ --logfile /data/ --jsonfile-pretty /data/ --csvfile /data/ --warnings=batch'

echo "autocompose - automatically create a docker compose file from a running container"
alias autocompose='sudo docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/red5d/docker-autocompose'

echo "cme - CrackMapExec docker edition - cme <args>"
alias cme='sudo docker run --rm -it --entrypoint=/usr/local/bin/cme --name crackmapexec-run -v "${PWD}/CrackMapExec-data:/root/.cme" byt3bl33d3r/crackmapexec'

echo "nmapfastscan - runs NMAP scanner; fast top1000 TCP; specify <IP's>"
alias nmapfastscan="docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -Pn -n --top-ports 1000 -vvvv --open --max-retries 3 --max-rtt-timeout 900ms --min-hostgroup 254 --min-rate 30000 --defeat-rst-ratelimit --host-timeout 1m "

echo "nmapfulltcpscan - runs NMAP scanner; all TCP ports; specify <IP's>"
alias nmapfulltcpscan="docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -n -Pn -p- -vvvv --open --min-rate 20000 --defeat-rst-ratelimit --host-timeout 5m -oA /tmp/nmap_fulltcp --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl "

echo "nmapservicescan - runs NMAP scanner; specific TCP ports; specify <IP's> and -p <PORTS>"
alias nmapservicescan="docker run --rm -it -v "${PWD}:/tmp" instrumentisto/nmap -sS -n -sV -vvvv --open -sC --script-timeout 15m -O -Pn -oA /tmp/nmap_servicescan "


echo "xingdumper -u <xing-company-url> - extracts XING employees as CSV"
alias xingdumper="python3 /opt/tools/osint/XingDumper/xingdumper.py"


echo "startnessus - Starts nessus on TCP/8834 - ensure you change the ACTIVATION_CODE before first use"
alias startnessus="docker run -d --name nessus-docker -p 8834:8834  -e ACTIVATION_CODE='XXXX-XXX-XXX-XXXX' -e USERNAME='vagrant' -e PASSWORD='vagrant' tenableofficial/nessus"

echo "sudomy - Subdomain Enumeration & Analysis; sudomy <domain>; runs sudomy docker container with --all flag and no nmap/gobuster; results in 'output' dir"
alias sudomy='cd /opt/tools/osint/sudomy && docker run -v "/opt/tools/osint/sudomy/output:/usr/lib/sudomy/output" -v "/opt/tools/osint/sudomy/sudomy.api:/usr/lib/sudomy/sudomy.api" -it --rm screetsec/sudomy:v1.2.0-dev -a -d'

echo "cleanhosts - ask laurent"
alias cleanhosts='sed -e "s/^http:\/\///g;s/^https:\/\///g" | sed "s/^*.//" | grep -e "\." | anew'

echo "purednsburte - DNS bruteforce - purednsbrute <wordlist> <domain> "
alias purednsbrute='puredns bruteforce -r /opt/tools/osint/dnsvalidator/resolvers.txt'

echo "shcheck - Security Header Check; shcheck <url> + <args>"
alias shcheck='python3 /opt/tools/infra/shcheck/shcheck.py '