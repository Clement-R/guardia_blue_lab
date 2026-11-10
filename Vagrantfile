# Lab Detection Engineering - libvirt network "detlab" (10.77.77.0/24)
# This file defines the SIEM VM. The Windows endpoint is created separately
# with virt-install, attached to the same "detlab" network.
# Host requirements: vagrant-libvirt and rsync.

NET = "10.77.77"

Vagrant.configure("2") do |config|
  config.vm.boot_timeout = 600

  # --- SIEM: Linux ---
  config.vm.define "siem" do |m|
    m.vm.box = "cloud-image/debian-13"
    m.vm.hostname = "siem"
    m.vm.network "private_network", ip: "#{NET}.10", libvirt__network_name: "detlab"
    m.vm.synced_folder ".", "/vagrant", type: "rsync",
      rsync__exclude: [".git/", ".vagrant/"]
    
    m.vm.provider "libvirt" do |libvirt|
      libvirt.driver = "kvm"
      libvirt.uri = 'qemu:///system'
      libvirt.memory = 6144
      libvirt.cpus = 2
      libvirt.machine_virtual_size = 60
    end

    m.vm.provision "shell", path: "provision/linux-base.sh"
    m.vm.provision "shell", path: "provision/elk.sh"
  end
end
