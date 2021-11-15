# k8s_training
training of k8s

## Installation
在Ubuntu 20.04下，No Docker模式国内安装最新K8S（1.22.3），网络插件flannel
>> master:192.168.1.13 <br>
>> worker1:192.168.1.10
```
Client Version: version.Info{Major:"1", Minor:"22", GitVersion:"v1.22.3", GitCommit:"c92036820499fedefec0f847e2054d824aea6cd1", GitTreeState:"clean", BuildDate:"2021-10-27T18:41:28Z", GoVersion:"go1.16.9", Compiler:"gc", Platform:"linux/amd64"}
```
- 集群节点环境准备 （master和worker）
```diff
- 用root账户
$ sudo su

- 关闭swap
$ sed -i '/swap/d' /etc/fstab
$ swapoff -a

- 关闭防火墙
$ systemctl disable --now ufw 

- 加载内核模块
$ cat >>/etc/modules-load.d/containerd.conf<<EOF
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

- 设置内核参数
$ cat >>/etc/sysctl.d/kubernetes.conf<<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
EOF
$ sysctl --system

- 安装并启动containerd
$ apt install containerd apt-transport-https
$ mkdir -p /etc/containerd
$ containerd config default > /etc/containerd/config.toml
$ systemctl restart containerd
$ systemctl enable containerd 

- 添加阿里源
$ curl https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg | apt-key add - 
$ apt-add-repository "deb https://mirrors.aliyun.com/kubernetes/apt/ kubernetes-xenial main"

- 安装k8s
$ apt install kubelet kubeadm kubectl

- 检查版本
$ kubelet --version
Kubernetes v1.22.3

- 阻止K8S更新
$ apt-mark hold kubeadm kubelet kubectl
```

- master节点配置
```diff
- 提前Pull需要的image
$ kubeadm config images pull --image-repository registry.aliyuncs.com/google_containers

- 把image打tag到k8s.gcr.io（这一步是必须的，否则kubeadm init依旧会到k8s.gcr.io下载镜像）
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/pause:3.5 k8s.gcr.io/pause:3.5
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-scheduler:v1.22.3 k8s.gcr.io/kube-scheduler:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-proxy:v1.22.3 k8s.gcr.io/kube-proxy:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-controller-manager:v1.22.3  k8s.gcr.io/kube-controller-manager:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-apiserver:v1.22.3 k8s.gcr.io/kube-apiserver:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/etcd:3.5.0-0  k8s.gcr.io/etcd:3.5.0-0
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/coredns:v1.8.4  k8s.gcr.io/coredns:v1.8.4

- 检查tag后的image list
$ crictl image list
k8s.gcr.io/coredns                                                v1.8.4              8d147537fb7d1       13.7MB
registry.aliyuncs.com/google_containers/coredns                   v1.8.4              8d147537fb7d1       13.7MB
k8s.gcr.io/etcd                                                   3.5.0-0             0048118155842       99.9MB
registry.aliyuncs.com/google_containers/etcd                      3.5.0-0             0048118155842       99.9MB
k8s.gcr.io/kube-apiserver                                         v1.22.3             53224b502ea4d       31.2MB
registry.aliyuncs.com/google_containers/kube-apiserver            v1.22.3             53224b502ea4d       31.2MB
k8s.gcr.io/kube-controller-manager                                v1.22.3             05c905cef780c       29.8MB
registry.aliyuncs.com/google_containers/kube-controller-manager   v1.22.3             05c905cef780c       29.8MB
k8s.gcr.io/kube-proxy                                             v1.22.3             6120bd723dced       35.9MB
registry.aliyuncs.com/google_containers/kube-proxy                v1.22.3             6120bd723dced       35.9MB
k8s.gcr.io/kube-scheduler                                         v1.22.3             0aa9c7e31d307       15MB
registry.aliyuncs.com/google_containers/kube-scheduler            v1.22.3             0aa9c7e31d307       15MB
k8s.gcr.io/pause                                                  3.5                 ed210e3e4a5ba       301kB
registry.aliyuncs.com/google_containers/pause                     3.5                 ed210e3e4a5ba       301kB
```
