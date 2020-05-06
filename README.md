# KALI_vagrant
quickly set up a new vagrant instance with KALI


Beforehand you need to install the vbguest plugin

$ vagrant plugin install vagrant-vbguest

After the install run the following commands from the terminal:
```
cp /home/vagrant/.bashrc /root/.bashrc
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases" > ~/.bash_aliases
curl -k -L -f "https://raw.githubusercontent.com/michiiii/KALI_vagrant/master/bash_aliases_root" > /root/.bash_aliases
```

