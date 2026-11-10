# Lab Detection Engineering - 3 VM sur on host-only network 10.77.77.0/24

# Linux/macOS : authorize range before "vagrant up" :
#   sudo mkdir -p /etc/vbox && echo "* 10.77.77.0/24" | sudo tee /etc/vbox/networks.conf

NET = "10.77.77"

Vagrant.configure("2") do |config|
  config.vm.boot_timeout = 600

  # --- SIEM: Linux ---
  config.vm.define "siem" do |m|
    m.vm.box = "cloud-image/debian-13"
    m.vm.hostname = "siem"
    m.vm.network "private_network", ip: "#{NET}.10"
    m.vm.network "forwarded_port", guest: 22, host: 2222, id: "ssh"
    m.vm.synced_folder ".", "/vagrant", type: "rsync",
      rsync__exclude: [".git/", ".vagrant/"]
    
     m.vm.provider "libvirt" do |libvirt|
      libvirt.driver = "kvm"
      libvirt.uri = 'qemu:///system'
      libvirt.memory = 6144
      libvirt.cpus = 2
      libvirt.machine_virtual_size = 40
    end

    m.vm.provision "shell", path: "provision/linux-base.sh"
    m.vm.provision "shell", path: "provision/elk.sh"
  end
end
