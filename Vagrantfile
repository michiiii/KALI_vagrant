# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "kalilinux/rolling"
  config.vm.hostname = "p41n"


  # Use bridge network. In VirtualBox
  config.vm.base_mac = "DEADBEEFCAFE"
  config.vm.network "public_network",  use_dhcp_assigned_default_route: true
  config.vm.synced_folder ".", "/vagrant"


  # Create a forwarded port if NAT
  # config.vm.network "forwarded_port", guest: 8090, host: 8090
  # config.vm.network "forwarded_port", guest: 8091, host: 8091
  # config.vm.network "forwarded_port", guest: 8091, host: 8091

  # Provision the machine with a shell script
  config.vm.provision :shell, path: "postinstall.sh"

  # VirtualBox guest plugin
  config.vbguest.auto_update = true
  
  # do NOT download the iso file from a webserver
  config.vbguest.no_remote = true

  # VirtualBox specific settings
  config.vm.provider "virtualbox" do |vb|
    
    vb.name = "KaliLinux_Vagrant"
    # Hide the VirtualBox GUI when booting the machine
    vb.gui = true

    vb.customize ["modifyvm", :id, "--clipboard-mode", "bidirectional"]

    #Customize CPUs assigned to machine
    vb.cpus = 2
    # Customize the amount of memory on the VM:
    vb.memory = "8192"
  end


end