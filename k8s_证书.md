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

