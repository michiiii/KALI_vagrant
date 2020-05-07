
# CUSTOM ALIASES

# Nice directory listings
alias ll="ls -l"
alias la="ls -la"
command -v lsd &> /dev/null && alias ls='lsd --group-dirs first -l'

command -v htop &> /dev/null && alias top='htop'

alias mirror='wget -mkEpnp -e robots=off'
alias unblock_dir='sudo chmod -R 755'
alias block_dir='sudo chmod -R 700'
alias web="sudo python -m SimpleHTTPServer"

alias pbcopy='xclip -selection clipboard'
alias pbpaste='xclip -selection clipboard -o'

## External IP Address
alias exip="curl https://ipinfo.io/ip"

## Unzip & untar
alias unzip="7z x -o* "
alias untar="tar -xvf "

## nmap
alias nmap="sudo nmap --reason --open --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit"

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
alias ports="netstat -tulanp"

## Get header
alias header="curl -I"

## Get external IP address
alias ipx="curl -s http://ipinfo.io/ip"

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

### HDD size
alias hogs="for i in G M K; do du -ah | grep [0-9]$i | sort -nr -k 1; done | head -n 11"

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
