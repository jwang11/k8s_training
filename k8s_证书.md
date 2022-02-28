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
/etc/kubernetes/pki
/etc/kubernetes/pki/etcd

## 集群根证书

Kubernetes 集群根证书CA(Kubernetes集群组件的证书签发机构)
/etc/kubernetes/pki/ca.crt
/etc/kubernetes/pki/ca.key

以上这组证书为签发其他Kubernetes组件证书使用的根证书, 可以认为是Kubernetes集群中的证书签发机构，由此根证书签发的证书有:

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

## 汇聚层证书
kube-apiserver的另一种访问方式就是使用kubectl proxy来代理访问, 而该证书就是用来支持SSL代理访问的。在该种访问模式下，用户是以http的方式发起请求到代理服务, 
代理服务会将该请求转发送给kube-apiserver。转发时, 代理会将请求头里加入证书信息, 以下两个配置

API Aggregation允许在不修改Kubernetes核心代码的同时扩展Kubernetes API. 开启 API Aggregation 需要在 kube-apiserver 中添加如下配置:
```diff
--requestheader-client-ca-file=<path to aggregator CA cert>
--requestheader-allowed-names=front-proxy-client
--requestheader-extra-headers-prefix=X-Remote-Extra-
--requestheader-group-headers=X-Remote-Group
--requestheader-username-headers=X-Remote-User
--proxy-client-cert-file=<path to aggregator proxy cert>
--proxy-client-key-file=<path to aggregator proxy key>
```

- kube-apiserver代理根证书(客户端证书)

用在requestheader-client-ca-file配置选项中, kube-apiserver使用该证书来验证客户端证书是否为自己所签发
/etc/kubernetes/pki/front-proxy-ca.crt
/etc/kubernetes/pki/front-proxy-ca.key

由此根证书签发的证书只有一组: 代理层(如汇聚层aggregator)使用此代理证书来向 kube-apiserver 请求认证

代理端使用的客户端证书, 用作代理用户与kube-apiserver认证
/etc/kubernetes/pki/front-proxy-client.crt
/etc/kubernetes/pki/front-proxy-client.key


## etcd集群根证书

etcd集群所用到的证书都保存在/etc/kubernetes/pki/etcd这路径下, 很明显, 这一套证书是用来专门给etcd集群服务使用的, 设计以下证书文件

etcd集群根证书CA(etcd 所用到的所有证书的签发机构)

/etc/kubernetes/pki/etcd/ca.crt
/etc/kubernetes/pki/etcd/ca.key
由此根证书签发机构签发的证书有:

- etcd server持有的服务端证书

/etc/kubernetes/pki/etcd/server.crt
/etc/kubernetes/pki/etcd/server.key

- peer集群中节点互相通信使用的客户端证书

/etc/kubernetes/pki/etcd/peer.crt
/etc/kubernetes/pki/etcd/peer.key

注: Peer：对同一个etcd集群中另外一个Member的称呼


- pod中定义 Liveness 探针使用的客户端证书

kubeadm部署的etcd服务是以pod方式运行, 在该pod的定义中, 配置了Liveness探活探针

/etc/kubernetes/pki/etcd/healthcheck-client.crt
/etc/kubernetes/pki/etcd/healthcheck-client.key

- 配置在kube-apiserver中用来与etcd server做双向认证的客户端证书

/etc/kubernetes/pki/apiserver-etcd-client.crt
/etc/kubernetes/pki/apiserver-etcd-client.key

## Serveice Account秘钥
这组”证书”其实不是证书, 而是一组秘钥。这组秘钥对儿其实跟我们在Linux上创建, 用于免密登录的密钥对儿原理是一样的

> 这组的密钥对儿仅提供给kube-controller-manager使用。 kube-controller-manager通过sa.key对token进行签名, master节点通过公钥sa.pub进行验证

/etc/kubernetes/pki/sa.key
/etc/kubernetes/pki/sa.pub

至此, kubeadm工具帮我们创建的所有证书文件都已经介绍完了, 整个Kubernetes&etcd集群中所涉及到的绝大部分证书都差不多在这里了。 有人可能会说，至少还少了一组证书呀, 就是kube-proxy持有的证书怎么没有自动生成呀. 因为kubeadm创建的集群, kube-proxy是以pod形式运行的, 在pod中, 直接使用service account与 kube-apiserver进行认证, 此时就不需要再单独为kube-proxy创建证书了。 如果你的 kube-proxy 是以守护进程的方式直接运行在宿主机的, 那么你就需要为它创建一套证书了。创建的方式也很简单, 直接使用上面第一条提到的Kubernetes集群根证书 进行签发就可以了(注意CN和O的设置)
