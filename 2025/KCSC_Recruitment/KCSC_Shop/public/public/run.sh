sudo docker pull tonistiigi/binfmt:latest
sudo docker run --privileged --rm tonistiigi/binfmt --uninstall qemu-*
sudo docker run --privileged --rm tonistiigi/binfmt --install all
sudo docker pull tonistiigi/binfmt:qemu-v6.2.0
sudo docker run --rm --privileged multiarch/qemu-user-static --reset -p yes -c yes

