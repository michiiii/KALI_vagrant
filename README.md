# KALI_vagrant
quickly set up a new vagrant instance with KALI


Beforehand you need to install the vbguest plugin
```
$ vagrant plugin install vagrant-vbguest
```

After the install run the following commands from the terminal:
```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/zshrc" > ~/.zshrc
source .zshrc
sudo -i
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > /root/.bash_aliases
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/zshrc_root" > ~/.zshrc
source .zshrc
exit
rm -r ~/.config/xfce4 
cp -r ~/KALI_vagrant/XFCE_config/xfce4 ~/.config/
sudo reboot now
```
Finally everything should be cool
