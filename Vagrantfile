# Lab Detection Engineering - libvirt network "detlab" (10.77.77.0/24)
#   siem  10.77.77.10  Debian 13, Elastic stack in Docker
#   dc    10.77.77.20  Windows Server 2025 Core, domain controller lab.local + Elastic Agent
# Host requirements: vagrant-libvirt and rsync.
# Order: "vagrant up siem" first (it exports the Windows enrollment bundle to .lab/), then "vagrant up dc".

NET = "10.77.77"

Vagrant.configure("2") do |config|
  config.vm.boot_timeout = 600

  # --- SIEM: Linux ---
  config.vm.define "siem" do |m|
    m.vm.box = "cloud-image/debian-13"
    m.vm.hostname = "siem"
    m.vm.network "private_network", ip: "#{NET}.10", libvirt__network_name: "detlab"
    m.vm.synced_folder ".", "/vagrant", type: "rsync",
      rsync__exclude: [".git/", ".vagrant/", ".lab/"]

    m.vm.provider "libvirt" do |libvirt|
      libvirt.driver = "kvm"
      libvirt.uri = 'qemu:///system'
      libvirt.memory = 6144
      libvirt.cpus = 2
      libvirt.machine_virtual_size = 60
    end

    m.vm.provision "shell", path: "provision/linux-base.sh"
    m.vm.provision "shell", path: "provision/elk.sh"

    # Copy the lab CA, enrollment token, stack version and Fleet URL to .lab/ on the host,
    # for the Windows provisioners. Uses plain ssh to avoid nesting vagrant commands.
    m.trigger.after [:up, :provision, :reload] do |t|
      t.name = "Export Windows enrollment bundle to .lab/"
      t.run = { inline: "bash -c 'mkdir -p .lab && ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
                        "-i .vagrant/machines/siem/libvirt/private_key vagrant@#{NET}.10 " \
                        "sudo tar -C /opt/elk/windows -cf - . | tar -C .lab -xf -'" }
    end
  end

  # --- Domain controller + monitored endpoint: Windows Server 2025 Core ---
  config.vm.define "dc" do |m|
    m.vm.box = "gusztavvargadr/windows-server-core"
    m.vm.box_version = "2607.0.0"
    m.vm.hostname = "dc01"
    m.vm.guest = :windows
    m.vm.communicator = "winrm"
    # After promotion "vagrant" is the domain account LAB\vagrant; the default Negotiate
    # login stalls. Basic auth over HTTP on the host-only management network (lab shortcut).
    m.winrm.transport = :plaintext
    m.winrm.basic_auth_only = true
    m.winrm.username = "vagrant"
    m.winrm.password = "vagrant"
    m.vm.boot_timeout = 900
    # Static IP is set by win-dc.ps1, which finds this NIC by its fixed MAC
    m.vm.network "private_network", ip: "#{NET}.20", libvirt__network_name: "detlab",
      mac: "52:54:00:77:77:20", auto_config: false
    m.vm.synced_folder ".", "/vagrant", disabled: true

    m.vm.provider "libvirt" do |libvirt|
      libvirt.driver = "kvm"
      libvirt.uri = 'qemu:///system'
      libvirt.memory = 4096
      libvirt.cpus = 2
    end

    %w[ca.crt enrollment-token stack-version fleet-url].each do |f|
      m.vm.provision "bundle-#{f}", type: "file", source: ".lab/#{f}", destination: "C:/lab/#{f}"
    end
    m.vm.provision "dc", type: "shell", path: "provision/win-dc.ps1", args: ["-Ip", "#{NET}.20", "-Gateway", "#{NET}.1"], reboot: true
    m.vm.provision "dc-post", type: "shell", path: "provision/win-dc-post.ps1", args: ["-Ip", "#{NET}.20", "-Forwarder", "#{NET}.1"]
    m.vm.provision "telemetry", type: "shell", path: "provision/win-telemetry.ps1"
    m.vm.provision "agent", type: "shell", path: "provision/win-agent.ps1"
  end
end
