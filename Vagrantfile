Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "kubedagger-dev"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4096
    vb.cpus = 2
  end

  config.vm.synced_folder ".", "/home/vagrant/KubeDagger"

  config.vm.provision "shell", path: "scripts/setup.sh"
end
