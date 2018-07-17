# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "centos-7.5-x86_64"
  config.vm.network "private_network", type: :dhcp
  config.vm.hostname = 'v-cis-c7.local'

  config.vm.provider "virtualbox" do |vb|
    # Display the VirtualBox GUI when booting the machine
    #vb.gui = true
  end
end
