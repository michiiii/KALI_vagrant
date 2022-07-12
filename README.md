# KALI_vagrant
quickly set up a new vagrant instance with KALI

After the install run the following commands from the vagrant ssh:
```
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
rm .zshrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/zshrc" > ~/.zshrc
source .zshrc
sudo -i
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > /root/.bash_aliases
rm .zshrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/zshrc_root" > ~/.zshrc
source .zshrc
exit
git clone https://github.com/michiiii/KALI_vagrant.git
cp -r ~/KALI_vagrant/XFCE_config/xfce4 ~/.config/
sudo reboot now
```
Finally everything should be cool
