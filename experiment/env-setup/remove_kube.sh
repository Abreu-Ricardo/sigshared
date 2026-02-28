#!/bin/bash

sudo rm -rf /etc/kubernetes/manifests/*
sudo systemctl stop kubelet
sudo systemctl stop docker    # or containerd, depending on your runtime
sudo systemctl stop containerd
sudo systemctl stop docker.socket
#
sudo lsof -i :6443
sudo lsof -i :10250

echo "Now Uninstalling Kubernetes and Cleaning Up"

# 1. Stop kubelet service
sudo systemctl stop kubelet || true

# 2. Remove Kubernetes packages
sudo apt-get purge -y kubelet kubeadm kubectl
sudo apt-mark unhold kubelet kubeadm kubectl || true

# 3. Remove Kubernetes apt repository
sudo rm -f /etc/apt/sources.list.d/kubernetes.list
sudo rm -f /etc/apt/keyrings/kubernetes-apt-keyring.gpg

# 4. Remove kubelet systemd customizations
sudo sed -i '/KUBELET_UNSAFE_SYSCTLS/d' /etc/systemd/system/kubelet.service.d/10-kubeadm.conf 2>/dev/null || true
sudo sed -i '/KUBELET_UNSAFE_SYSCTLS/d' /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf 2>/dev/null || true

# 5. Reload systemd daemon
sudo systemctl daemon-reload

# 6. Clean up leftover configuration and manifests (optional)
sudo rm -rf /etc/kubernetes
sudo rm -rf /var/lib/etcd
sudo rm -rf /var/lib/kubelet
sudo rm -rf /etc/systemd/system/kubelet.service.d

# 7. Remove unused dependencies
sudo apt-get autoremove -y
sudo apt-get clean

echo -e "\n\nFinished Uninstalling Kubernetes and Cleaning Up\n\n"
