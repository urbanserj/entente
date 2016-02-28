# -*- mode: ruby -*-
# vi: set ft=ruby :

require 'vagrant-vbguest'

Vagrant.configure(2) do |config|
  config.vm.box = "debian/jessie64"

  config.vm.network :forwarded_port, guest: 3890, host: 3890
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.synced_folder ".", "/home/vagrant/entente"

  config.vm.provider "virtualbox" do |v|
    v.linked_clone = true
  end

  config.vm.provision :shell, inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y make gcc clang clang-format-3.5 libpam-dev libev-dev gdb lldb valgrind curl
    sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100
    sudo ln -s `which clang-format-3.5` /usr/local/bin/clang-format
  SHELL
end
