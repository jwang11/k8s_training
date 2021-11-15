# k8s_training
training of k8s

## Installation
在Ubuntu 20.04下，No Docker模式国内安装最新K8S（1.22.3），网络插件flannel
>> master:192.168.1.13 <br>
>> worker1:192.168.1.10
```
Client Version: version.Info{Major:"1", Minor:"22", GitVersion:"v1.22.3", GitCommit:"c92036820499fedefec0f847e2054d824aea6cd1", GitTreeState:"clean", BuildDate:"2021-10-27T18:41:28Z", GoVersion:"go1.16.9", Compiler:"gc", Platform:"linux/amd64"}
```

### 所有集群节点
- 集群节点环境准备
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

### Master节点
- Master节点配置
```diff
- 检查kubeadm需要的image list
$ kubeadm config images list
k8s.gcr.io/kube-apiserver:v1.22.3
k8s.gcr.io/kube-controller-manager:v1.22.3
k8s.gcr.io/kube-scheduler:v1.22.3
k8s.gcr.io/kube-proxy:v1.22.3
k8s.gcr.io/pause:3.5
k8s.gcr.io/etcd:3.5.0-0
k8s.gcr.io/coredns/coredns:v1.8.4

- 从国内阿里库Pull上面的image list
$ kubeadm config images pull --image-repository registry.aliyuncs.com/google_containers

- 打tag到k8s.gcr.io（这一步是必须的，否则kubeadm init依旧会到k8s.gcr.io下载镜像）
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/pause:3.5 k8s.gcr.io/pause:3.5
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-scheduler:v1.22.3 k8s.gcr.io/kube-scheduler:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-proxy:v1.22.3 k8s.gcr.io/kube-proxy:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-controller-manager:v1.22.3  k8s.gcr.io/kube-controller-manager:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-apiserver:v1.22.3 k8s.gcr.io/kube-apiserver:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/etcd:3.5.0-0  k8s.gcr.io/etcd:3.5.0-0
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/coredns:v1.8.4  k8s.gcr.io/coredns:v1.8.4

- 检查tag后的image list
$ crictl --runtime-endpoint unix:///run/containerd/containerd.sock image
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

- Master节点初始化cluster
```diff
- 因为准备用flannel网络插件，设置--pod-network-cidr=10.244.0.0/16
$ kubeadm init --image-repository registry.aliyuncs.com/google_containers --pod-network-cidr=10.244.0.0/16
[init] Using Kubernetes version: v1.22.3
[preflight] Running pre-flight checks
[preflight] Pulling images required for setting up a Kubernetes cluster
[preflight] This might take a minute or two, depending on the speed of your internet connection
[preflight] You can also perform this action in beforehand using 'kubeadm config images pull'
[certs] Using certificateDir folder "/etc/kubernetes/pki"
[certs] Generating "ca" certificate and key
[certs] Generating "apiserver" certificate and key
[certs] apiserver serving cert is signed for DNS names [kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local master.local] and IPs [10.96.0.1 192.168.1.13]
[certs] Generating "apiserver-kubelet-client" certificate and key
[certs] Generating "front-proxy-ca" certificate and key
[certs] Generating "front-proxy-client" certificate and key
[certs] Generating "etcd/ca" certificate and key
[certs] Generating "etcd/server" certificate and key
[certs] etcd/server serving cert is signed for DNS names [localhost master.local] and IPs [192.168.1.13 127.0.0.1 ::1]
[certs] Generating "etcd/peer" certificate and key
[certs] etcd/peer serving cert is signed for DNS names [localhost master.local] and IPs [192.168.1.13 127.0.0.1 ::1]
[certs] Generating "etcd/healthcheck-client" certificate and key
[certs] Generating "apiserver-etcd-client" certificate and key
[certs] Generating "sa" key and public key
[kubeconfig] Using kubeconfig folder "/etc/kubernetes"
[kubeconfig] Writing "admin.conf" kubeconfig file
[kubeconfig] Writing "kubelet.conf" kubeconfig file
[kubeconfig] Writing "controller-manager.conf" kubeconfig file
[kubeconfig] Writing "scheduler.conf" kubeconfig file
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Starting the kubelet
[control-plane] Using manifest folder "/etc/kubernetes/manifests"
[control-plane] Creating static Pod manifest for "kube-apiserver"
[control-plane] Creating static Pod manifest for "kube-controller-manager"
[control-plane] Creating static Pod manifest for "kube-scheduler"
[etcd] Creating static Pod manifest for local etcd in "/etc/kubernetes/manifests"
[wait-control-plane] Waiting for the kubelet to boot up the control plane as static Pods from directory "/etc/kubernetes/manifests". This can take up to 4m0s
[apiclient] All control plane components are healthy after 12.005604 seconds
[upload-config] Storing the configuration used in ConfigMap "kubeadm-config" in the "kube-system" Namespace
[kubelet] Creating a ConfigMap "kubelet-config-1.22" in namespace kube-system with the configuration for the kubelets in the cluster
[upload-certs] Skipping phase. Please see --upload-certs
[mark-control-plane] Marking the node master.local as control-plane by adding the labels: [node-role.kubernetes.io/master(deprecated) node-role.kubernetes.io/control-plane node.kubernetes.io/exclude-from-external-load-balancers]
[mark-control-plane] Marking the node master.local as control-plane by adding the taints [node-role.kubernetes.io/master:NoSchedule]
[bootstrap-token] Using token: yrrkd1.d5m6fd6stj51nkrf
[bootstrap-token] Configuring bootstrap tokens, cluster-info ConfigMap, RBAC Roles
[bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to get nodes
[bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to post CSRs in order for nodes to get long term certificate credentials
[bootstrap-token] configured RBAC rules to allow the csrapprover controller automatically approve CSRs from a Node Bootstrap Token
[bootstrap-token] configured RBAC rules to allow certificate rotation for all node client certificates in the cluster
[bootstrap-token] Creating the "cluster-info" ConfigMap in the "kube-public" namespace
[kubelet-finalize] Updating "/etc/kubernetes/kubelet.conf" to point to a rotatable kubelet client certificate and key
[addons] Applied essential addon: CoreDNS
[addons] Applied essential addon: kube-proxy

Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:
- 下面三行命令，Master节点从普通用户登录执行
  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config
Alternatively, if you are the root user, you can run:

  export KUBECONFIG=/etc/kubernetes/admin.conf

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:

- 下面这段命令Copy下来，worker加入Cluster时调用
kubeadm join 192.168.1.13:6443 --token yrrkd1.d5m6fd6stj51nkrf \
        --discovery-token-ca-cert-hash sha256:639025d1f27609aa5d966defbfa80e0569246c9b61c4bb37c80d56a2f0edbe3b
```
- Master节点配置kubectl命令执行环境
```
$ mkdir -p $HOME/.kube
$ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
$ sudo chown $(id -u):$(id -g) $HOME/.kube/config

$ kubectl get nodes
NAME           STATUS   ROLES                  AGE   VERSION
master.local   Ready    control-plane,master   17m   v1.22.3
```
- Master节点安装Flannel网络插件
```diff
$ kubectl apply -f https://github.com/flannel-io/flannel/blob/master/Documentation/kube-flannel.yml

- 如果https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml不能直接访问
- 下载到本地安装
$ kubectl apply -f kube-flannel.yml
Warning: policy/v1beta1 PodSecurityPolicy is deprecated in v1.21+, unavailable in v1.25+
podsecuritypolicy.policy/psp.flannel.unprivileged created
clusterrole.rbac.authorization.k8s.io/flannel created
clusterrolebinding.rbac.authorization.k8s.io/flannel created
serviceaccount/flannel created
configmap/kube-flannel-cfg created
daemonset.apps/kube-flannel-ds created
```

### Worker节点
- Worker节点配置
```diff
- Worker节点不需要全部kubeadm config images list，仅需要两个
 k8s.gcr.io/kube-proxy:v1.22.3
 k8s.gcr.io/pause:3.5

- 从阿里库pull image
$ crictl --runtime-endpoint unix:///run/containerd/containerd.sock pull registry.aliyuncs.com/google_containers/kube-proxy:v1.22.3
$ crictl --runtime-endpoint  unix:///run/containerd/containerd.sock pull registry.aliyuncs.com/google_containers/pause:3.5

- 给Image打上k8s.gcr.io tag
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/kube-proxy:v1.22.3 k8s.gcr.io/kube-proxy:v1.22.3
$ ctr -n k8s.io i tag --force registry.aliyuncs.com/google_containers/pause:3.5 k8s.gcr.io/pause:3.5
```

- 加入Cluster（从Master节点kubeadm init的输出里直接Copy）
```diff
$ kubeadm join 192.168.1.13:6443 --token yrrkd1.d5m6fd6stj51nkrf  --discovery-token-ca-cert-hash sha256:639025d1f27609aa5d966defbfa80e0569246c9b61c4bb37c80d56a2f0edbe3b
[preflight] Running pre-flight checks
[preflight] Reading configuration from the cluster...
[preflight] FYI: You can look at this config file with 'kubectl -n kube-system get cm kubeadm-config -o yaml'
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Starting the kubelet
[kubelet-start] Waiting for the kubelet to perform the TLS Bootstrap...

This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the control-plane to see this node join the cluster.

```

### Cluster操作
从Control Plane（Master节点上普通用户登录的终端）操作cluster
```diff
jwang@master:~$ kubectl get node -o wide
NAME           STATUS   ROLES                  AGE    VERSION   INTERNAL-IP    EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION      CONTAINER-RUNTIME
jwang-pc2      Ready    <none>                 49m    v1.22.3   192.168.1.10   <none>        Ubuntu 20.04.2 LTS   5.4.0-90-generic    containerd://1.5.5
master.local   Ready    control-plane,master   169m   v1.22.3   192.168.1.13   <none>        Ubuntu 20.04.3 LTS   5.11.0-40-generic   containerd://1.5.5

$ kubectl get pod -A -o wide
NAMESPACE     NAME                                   READY   STATUS    RESTARTS   AGE    IP             NODE           NOMINATED NODE   READINESS GATES
kube-system   coredns-7f6cbbb7b8-bc2qc               1/1     Running   0          160m   10.244.0.2     master.local   <none>           <none>
kube-system   coredns-7f6cbbb7b8-g7xr5               1/1     Running   0          160m   10.244.0.3     master.local   <none>           <none>
kube-system   etcd-master.local                      1/1     Running   3          160m   192.168.1.13   master.local   <none>           <none>
kube-system   kube-apiserver-master.local            1/1     Running   3          160m   192.168.1.13   master.local   <none>           <none>
kube-system   kube-controller-manager-master.local   1/1     Running   3          160m   192.168.1.13   master.local   <none>           <none>
kube-system   kube-flannel-ds-qv9zv                  1/1     Running   0          40m    192.168.1.10   jwang-pc2      <none>           <none>
kube-system   kube-flannel-ds-zz879                  1/1     Running   0          132m   192.168.1.13   master.local   <none>           <none>
kube-system   kube-proxy-mlxcd                       1/1     Running   0          40m    192.168.1.10   jwang-pc2      <none>           <none>
kube-system   kube-proxy-q4jjz                       1/1     Running   0          160m   192.168.1.13   master.local   <none>           <none>
kube-system   kube-scheduler-master.local            1/1     Running   3          160m   192.168.1.13   master.local   <none>           <none>
```
