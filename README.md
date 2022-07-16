# KALI_vagrant
quickly set up a new vagrant instance with KALI

After the install run the following commands from the vagrant ssh:
```bash
sudo apt install git curl zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
rm .zshrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/zshrc" | sed "s/vagrant/$USER/g" > ~/.zshrc
source .zshrc
sudo -i
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
rm .zshrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/zshrc" | sed "s/vagrant/$USER/g" > ~/.zshrc
source .zshrc
exit
git clone https://github.com/michiiii/KALI_vagrant.git
cp -r ~/KALI_vagrant/XFCE_config/xfce4 ~/.config/
sudo reboot now
```
Finally everything should be cool
