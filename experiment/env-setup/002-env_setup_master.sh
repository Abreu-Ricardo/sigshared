#/bin/bash
# This script can be run with non-root user

cd /mydata # Use the extended disk with enough space

#####################################################################
sudo apt install -y ninja-build python3 git \
  build-essential libedit-dev libncurses5-dev zlib1g-dev \
  libxml2-dev libsqlite3-dev swig libssl-dev zlib1g zlib1g-dev

echo "Installing CMake"
git clone -b v4.2.0 https://github.com/Kitware/CMake
cd CMake
./bootstrap
make -j$(nproc)
sudo make install
cd ../

#####################################################################
echo "Installing llvm"

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

cd ../../

#####################################################################
# libbpf v1.6
echo "Installing libbpf v1.6"
git clone -b v1.6.0 https://github.com/libbpf/libbpf

cd libbpf/src
make -j$(nproc)

echo "/usr/lib64/" | sudo tee -a /etc/ld.so.conf
sudo make install

cd ../../

#####################################################################
# BPFTOOL
echo "Installing bpftool"
sudo apt install libbfd-dev libcap-dev libbpf-dev

git clone -b v7.6.0 --recurse-submodules https://github.com/libbpf/bpftool

cd bpftool/src
make -j$(nproc)
sudo make install

cd ../../

##################################################
# libxdp
echo "Installing libxdp"
git clone --recurse-submodules https://github.com/xdp-project/xdp-tools

cd ./xdp-tools/
./configure
make -j$(nproc)
sudo make install
sudo ldconfig # para atribuir as alteracoes ja instaladas

cd ../

#####################################################################
#echo "Installing libbpf"
#git clone --single-branch https://github.com/libbpf/libbpf.git
#cd libbpf
#git switch --detach v0.6.0
#cd src
#make -j $(nproc)
#sudo make install
#echo "/usr/lib64/" | sudo tee -a /etc/ld.so.conf
#sudo ldconfig
#cd ../..

#echo "Installing DPDK"
#cd /mydata # Use the extended disk with enough space
#
#git clone --single-branch git://dpdk.org/dpdk
#cd dpdk
#git switch --detach v21.11
#meson build
#cd build
#ninja
#sudo ninja install
#sudo ldconfig
#cd ../..

echo "Set up hugepages"
sudo sysctl -w vm.nr_hugepages=16384

#echo "build SPRIGHT"
echo "build sigshared"
cd /mydata # Use the extended disk with enough space

#git clone https://github.com/ucr-serverless/spright.git
git clone https://github.com/Abreu-Ricardo/sigshared.git
#cd spright/src/cstl && make
cd sigshared/src/cstl && make
cd ../../ && make


echo "export SIGSHARED=/mydata/sigshared" >> ~/.bashrc
source ~/.bashrc

cd /mydata/sigshared
sudo mount -t bpf bpffs /sys/fs/bpf
sudo mount --bind /sys/fs/bpf ./dados;

echo "Enable eBPF CPU usage record < echo 1 > /proc/sys/kernel/bpf_stats_enabled > "
