# K8S 证书

用kubeadm创建完Kubernetes集群后, 默认会在/etc/kubernetes/pki目录下存放集群中需要用到的证书文件
```diff
/etc/kubernetes/pki$ tree
.
├── apiserver.crt
├── apiserver-etcd-client.crt
├── apiserver-etcd-client.key
├── apiserver.key
├── apiserver-kubelet-client.crt
├── apiserver-kubelet-client.key
├── ca.crt
├── ca.key
├── etcd
│   ├── ca.crt
│   ├── ca.key
│   ├── healthcheck-client.crt
│   ├── healthcheck-client.key
│   ├── peer.crt
│   ├── peer.key
│   ├── server.crt
│   └── server.key
├── front-proxy-ca.crt
├── front-proxy-ca.key
├── front-proxy-client.crt
├── front-proxy-client.key
├── sa.key
└── sa.pub
 
1 directory, 22 files
```

## 证书分组

Kubernetes把证书放在了两个文件夹中，共22个文件
- /etc/kubernetes/pki
- /etc/kubernetes/pki/etcd

## 集群根证书

- Kubernetes 集群根证书CA(Kubernetes集群组件的证书签发机构)
- /etc/kubernetes/pki/ca.crt
- /etc/kubernetes/pki/ca.key

以上这组证书为签发其他Kubernetes组件证书使用的根证书, 可以认为是Kubernetes集群中的证书签发机构
由此根证书签发的证书有:

- kube-apiserver 组件持有的服务端证书
/etc/kubernetes/pki/apiserver.crt
/etc/kubernetes/pki/apiserver.key

- kubelet 组件的客户端证书, 用作 kube-apiserver 主动向 kubelet 发起请求时的客户端认证
/etc/kubernetes/pki/apiserver-kubelet-client.crt
/etc/kubernetes/pki/apiserver-kubelet-client.key

注意: Kubernetes集群组件之间的交互是双向的, kubelet既需要主动访问kube-apiserver, kube-apiserver也需要主动向 kubelet发起请求, 
所以双方都需要有自己的根证书以及使用该根证书签发的服务端证书和客户端证书。

在kube-apiserver中, 一般明确指定用于https访问的服务端证书和带有CN用户名信息的客户端证书，而在kubelet的启动配置中, 一般只指定了ca根证书, 
而没有明确指定用于https访问的服务端证书, 这是因为在生成服务端证书时, 一般会指定服务端地址或主机名, kube-apiserver相对变化不是很频繁, 所以在创建
集群之初就可以预先分配好用作kube-apiserver的IP或主机名/域名, 但是由于部署在node节点上的kubelet会因为集群规模的变化而频繁变化, 而无法预知node
的所有IP信息, 所以kubelet上一般不会明确指定服务端证书, 而是只指定ca根证书, 让kubelet根据本地主机信息自动生成服务端证书并保存到配置的cert-dir文件夹中。

