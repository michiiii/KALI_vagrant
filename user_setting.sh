#!/bin/bash 

git clone https://github.com/michiiii/KALI_vagrant.git

rm -r ~/.config/xfce4 
cp -r ~/KALI_PostInstall/XFCE_config/xfce4 ~/.config/
cp /home/vagrant/.bashrc /root/.bashrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases_root" > /root/.bash_aliases