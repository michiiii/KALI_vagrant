# KALI_vagrant
quickly set up a new vagrant instance with KALI


Beforehand you need to install the vbguest plugin
```
$ vagrant plugin install vagrant-vbguest
```

After the install run the following commands from the terminal:
```
git clone https://github.com/michiiii/KALI_vagrant
sudo cp /home/vagrant/.bashrc /root/.bashrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
sudo -i
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases_root" > /root/.bash_aliases
reboot now
```
Finally get the user settings
```
rm -r ~/.config/xfce4 
cp -r ~/KALI_vagrant/XFCE_config/xfce4 ~/.config/
sudo reboot now
```
