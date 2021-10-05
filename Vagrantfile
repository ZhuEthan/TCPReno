# -*- mode: ruby -*-
# vi: set ft=ruby :

$INSTALL_BASE = <<SCRIPT
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential vim emacs tree tmux git gdb valgrind python-dev libffi-dev libssl-dev clang-format iperf3 tshark
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python python3-pip python-tk

  pip install --upgrade pip
  pip install tcconfig scapy fabric typing cryptography scapy matplotlib pytest fabric
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/focal64"
  config.ssh.forward_agent = true
  config.vm.provision "shell", inline: $INSTALL_BASE
  config.vm.synced_folder "15-441-project-2", "/vagrant/15-441-project-2"
  # config.vm.provider "virtualbox" do |vb|
  #    # Display the VirtualBox GUI when booting the machine
  #    #   Username: vagrant
  #    #   Password: vagrant
  #   
  #    vb.gui = true
  #    # Customize the amount of memory on the VM:
  #    vb.memory = "1024"
  # end

  config.vm.define :client, primary: true do |host|
    host.vm.hostname = "client"
    host.vm.network "private_network", ip: "10.0.0.2", netmask: "255.255.255.0", mac: "080027a7feb1",
                    virtualbox__intnet: "15441"
    host.vm.provision "shell", inline: "sudo tcset enp0s8 --rate 100Mbps --delay 20ms"
    host.vm.provision "shell", inline: "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config"
    host.vm.provision "shell", inline: "sudo service sshd restart"
  end

  config.vm.define :server do |host|
    host.vm.hostname = "server"
    host.vm.network "private_network", ip: "10.0.0.1", netmask: "255.255.255.0", mac: "08002722471c",
                    virtualbox__intnet: "15441"
    host.vm.provision "shell", inline: "sudo tcset enp0s8 --rate 100Mbps --delay 20ms"
    host.vm.provision "shell", inline: "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config"
    host.vm.provision "shell", inline: "sudo service sshd restart"
  end
end
