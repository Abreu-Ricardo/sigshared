#!/bin/bash

# 1- CMake 
# 2- LLVM
# 3- libbpf v1.6
# 4- bpftool v1.6
# 5- libxdp

# prerequisitos do LLVM
sudo apt install -y ninja-build python3 git \
  build-essential libedit-dev libncurses5-dev zlib1g-dev \
  libxml2-dev libsqlite3-dev swig libssl-dev zlib1g zlib1g-dev

##################################################
# CMake
#git clone https://github.com/Kitware/CMake
git clone -b v4.2.0 https://github.com/Kitware/CMake
cd CMake
./bootstrap
make -j$(nproc)
sudo make install
cd ../

##################################################
# LLVM --> N TA INSTALANDO NO SISTEMA 
git clone --depth 1 https://github.com/llvm/llvm-project.git

cd llvm-project
mkdir build
cd build

# Compila o clang e o lld e poe na pasta /usr/local que eh o default
# Compila tbm para as arquiteturas x_86 e BPF
cmake -G Ninja ../llvm \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_INSTALL_PREFIX=/usr/local

ninja
sudo ninja install

#cd ../../sudo make install
cd ../../

##################################################
# libbpf v1.6
git clone -b v1.6.0 https://github.com/libbpf/libbpf

cd libbpf/src
make -j$(nproc)
sudo make install

cd ../../

##################################################
# BPFTOOL
sudo apt install libbfd-dev libcap-dev libbpf-dev

git clone -b v7.6.0 --recurse-submodules https://github.com/libbpf/bpftool
cd bpftool/src
make -j$(nproc)
sudo make install

cd ../../

##################################################
# libxdp
git clone --recurse-submodules https://github.com/xdp-project/xdp-tools

cd ./xdp-tools/
./configure
make -j$(nproc)
sudo make install

sudo ldconfig # para atribuir as alteracoes ja instaladas
# As vezes eh necessario usar sudo ldconfig
# para salvar as configs realizadas


#################################################
# Criar variavel do ambiente --> echo "export SIGSHARED=/mydata/spright" >> ~/.bashrc
# source ~/.bashrc
# Copiar: o dir ebpf/*, Makefile e o dir src/*

# Criar o diretorio /mydata/spright/dados
# sudo mount -t bpf bpffs /sys/fs/bpf
# sudo mount --bind /sys/fs/bpf ./dados;

# Poder capturar a quantidade de tempo de CPU do programa eBPF, mas isso adiciona 20ns no tempo de execucao
# sudo su;
# echo 1 > /proc/sys/kernel/bpf_stats_enabled ;

# dar permissao para o usuario sudo chown ricardoA dados
# Arrumar interface para se acoplar --> eh o indice da interface com 10.10.1.1


# Para travar o clock da cpu da maquina c220g5
# no arquivo /etc/default/grub--> GRUB_CMDLINE_LINUX_DEFAULT="intel_pstate=disable intel_idle.max_cstate=0  nosmt isolcpus=0,1,2,3,4,5,6,7,8,9"
# sudo apt install linux-tools-$(uname -r)    para baixar o CPUPOWER e settar os clocks
# sudo update-grub
# sudo reboot

    # Pra desativar o modo boost da CPU
# echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
    # Travando o freq da CPU
# sudo cpupower -c all frequency-set -d 2.2GHz -u 2.2GHz
# sudo cpupower -c all frequency-set -g ondemand 

    # Para usar o locust com constant_thoughput usar o locust 2.25 que eh a versao mais nova possivel de acessar nesse kernel
# Alterar as configuracoes de instalacao do Locust para o 2.25
