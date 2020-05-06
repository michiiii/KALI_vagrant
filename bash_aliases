# autocomplete addon
bind 'TAB:menu-complete'
bind 'set show-all-if-ambiguous on'

# colorful man pages
export LESS_TERMCAP_mb=$'\e[1;32m'
export LESS_TERMCAP_md=$'\e[1;32m'
export LESS_TERMCAP_me=$'\e[0m'
export LESS_TERMCAP_se=$'\e[0m'
export LESS_TERMCAP_so=$'\e[01;33m'
export LESS_TERMCAP_ue=$'\e[0m'
export LESS_TERMCAP_us=$'\e[1;4;31m'

# CUSTOM PROMPT
OS_ICON = "#" 
## regular user account; orange background
PS1="\n \[\033[0;34m\]╭─\[\033[0;33m\]\[\033[0;30m\]\[\033[43m\] $OS_ICON \d  \u \[\033[0m\]\[\033[0;33m\]\[\033[44m\]\[\033[0;34m\]\[\033[44m\]\[\033[0;30m\]\[\033[44m\] \w \[\033[0m\]\[\033[0;34m\] \n \[\033[0;34m\]╰> \[\033[1;36m\]\$ \[\033[0m\]"
## root user account; red background
#PS1="\n \[\033[0;34m\]╭─\[\033[0;31m\]\[\033[0;37m\]\[\033[41m\] $OS_ICON \d  \u \[\033[0m\]\[\033[0;31m\]\[\033[44m\]\[\033[0;34m\]\[\033[44m\]\[\033[0;30m\]\[\033[44m\] \w \[\033[0m\]\[\033[0;34m\] \n \[\033[0;34m\]╰> \[\033[1;36m\]\$ \[\033[0m\]"

# CUSTOM FUNCTIONS
## find nmapscripts
function nmapscripts() {
    find /usr/share/nmap/scripts/ -exec basename {} \; | grep -i "$1" | column
}
## rewrite find command
function find() {
    if [ $# = 1 ];
    then
        command find . -iname "*$@*"
    else
        command find "$@"
    fi
}



# CUSTOM ALIASES
alias ll="ls -l"
alias la="ls -la"

command -v lsd &> /dev/null && alias ls='lsd --group-dirs first -l'
command -v htop &> /dev/null && alias top='htop'

alias mirror='wget -mkEpnp -e robots=off'
alias unblock_dir='sudo chmod -R 755'
alias block_dir='sudo chmod -R 700'
alias web="sudo python -m SimpleHTTPServer "

alias pbcopy='xclip -selection clipboard'
alias pbpaste='xclip -selection clipboard -o'
alias exip="curl https://ipinfo.io/ip"
alias unzip="7z x -o* "
alias untar="tar -xvf "

alias onetwopunch="sudo /opt/tools/misc/onetwopunch/./onetwopunch.sh"
alias cap2hccapx="/usr/share/hashcat/master/hashcat-utils-master/src/cap2hccapx.bin"
alias nmap="sudo nmap"
alias install="sudo apt-get install"
alias search="sudo apt-cache search"
alias responder="sudo python /opt/tools/exploit/Responder/Responder.py"

alias htb.vpn="sudo openvpn /opt/vpn/htb.ovpn"
alias vpn="sudo openvpn /opt/vpn/ptf.ovpn"
alias work="cd /opt/projects/"
alias htb="cd /opt/htb"