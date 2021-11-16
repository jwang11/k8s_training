## K8S Service服务

Kubernetes中定义了一种名为Service的抽象，用于对Pod进行逻辑分组，并定义了网络分组访问策略。(注意，service不管理Pod，它是一种网络服务发现）
一组Pod能够被Service访问，通常是通过标签选择器（label selector）来确定是哪些Pod的。
虽然后端Pod的IP可能会发生变化，但前端客户端不需要知道这一点，也不必跟踪后端的变化，通过Service可以自动跟踪这种关联。
除此之外，还可以使用Ingress来发布服务。Ingress并不是某种服务类型，可以充当集群的入口。
Ingress支持将路由规则合并到单个资源中，在同一IP地址下发布多个服务。


### Service分类
Service目前可定义为5个大类。通过spec.type属性可定义ClusterIP、NodePort、LoadBalancer、ExternalName这4类Service，而ClusterIP类服务还可以分为普通Service和无头Service两类，所以总共分为5类。它们分别适用于各种向外发布的场景和向内发布的场景。

三种是从内向外发布服务
- 普通Service：这是默认方式，使用时可以不填写spec.type。在Kubernetes集群内部发布服务时，会为Service分配一个集群内部可以访问的固定虚拟IP（即ClusterIP）地址。集群中的机器（即Master和Node）以及集群中的Pod都可以访问这个IP地址。
- NodePort：这种方式基于ClusterIP方式，先生成一个ClusterIP地址，然后将这个IP地址及端口映射到各个集群机器（即Master和Node）的指定端口上。这样，Kubernetes集群外部的机器就可以通过“NodeIP:Node端口”方式访问Service。
- LoadBalancer：这种方式基于ClusterIP方式和NodePort方式，除此以外，还会申请使用外部负载均衡器，由负载均衡器映射到各个“NodeIP:端口”上。这样，Kubernetes集群外部的机器就可以通过负载均衡器访问Service。

两种是从外向内引入服务
- ClusterIP-无头Service（headless service）：这种方式不会分配ClusterIP地址，也不通过kube-proxy进行反向代理和负载均衡，而是通过DNS提供稳定的网络ID来进行访问。DNS会将无头Service的后端直接解析为Pod的IP地址列表。这种类型的Service只能在集群内的Pod中访问，集群中的机器无法直接访问。这种方式主要供StatefulSet使用。
- ExternalName：和上面提到的3种向外发布的方式不太一样，在那3种方式中都将Kubernetes集群内部的服务发布出去，而ExternalName则将外部服务引入进来，通过一定格式映射到Kubernetes集群，从而为集群内部提供服务。

### ClusterIP
- 通过deployment创建一组pods，标签example=forservice
```diff
apiVersion: apps/v1
kind: Deployment
metadata:
  name: exampleservice
spec:
  replicas: 3
  selector:
    matchLabels:
      example: forservice
  template:
    metadata:
      labels:
        example: forservice
    spec:
      containers:
      - name: pythonservice
        image: python:3.7
        imagePullPolicy: IfNotPresent
        command: ['sh', '-c']
        args: ['echo "<p>The host is $(hostname)</p>" > index.html; python -m http.server 80']
        ports:
          - name: http
            containerPort: 80
```
- 再单独创建一个Pod，打上标签example=forservice
```diff
apiVersion: v1
kind: Pod
metadata:
  name: examplepod
  labels:
    example: forservice
spec:
  containers:
  - name: pythonservice
    image: python:3.7
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c']
    args: ['echo "<p>The host is pod_example</p>" > index.html; python -m http.server 80']
    ports:
      - name: http
        containerPort: 80
```
现在有4个标签为example=forservice的Pods
```diff
$ kubectl get pods
NAME                              READY   STATUS    RESTARTS   AGE
examplepod                        1/1     Running   0          88m
exampleservice-78d6997f86-n7wz6   1/1     Running   0          106m
exampleservice-78d6997f86-s245p   1/1     Running   0          106m
exampleservice-78d6997f86-wsjsl   1/1     Running   0          106m
```

- 创建ClusterIP服务，关联到标签为example=forservice的Pods
```diff
kind: Service
apiVersion: v1
metadata:
  name: clusteripservice
spec:
  selector:
    example: forservice
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 80
  type: ClusterIP
```

- 简单测试
```diff
$ kubectl get service -o wide
NAME               TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE   SELECTOR
clusteripservice   ClusterIP   10.110.244.138   <none>        8080/TCP         89m   example=forservice

- Cluster-IP是10.110.244.138
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-s245p</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-wsjsl</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-wsjsl</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-wsjsl</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 10.110.244.138:8080
<p>The host is pod_example</p>
$ curl 10.110.244.138:8080
<p>The host is pod_example</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-s245p</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-wsjsl</p>
$ curl 10.110.244.138:8080
<p>The host is exampleservice-78d6997f86-n7wz6</p>
```

- 原理分析

为什么这4个Pods关联了Service以后，就可以实现负载均衡了呢？在每个节点中都有一个叫作kube-proxy的组件，这个组件识别Service和Pod的动态变化，并将变化的地址信息写入本地的IPTables中。而IPTables使用NAT等技术将virtualIP的流量转至Endpoint。默认情况下，Kubernetes使用的是IPTables模式
```diff
$ sudo iptables -L -v -n -t natsudo iptables -L -v -n -t nat
Chain PREROUTING (policy ACCEPT 2 packets, 627 bytes)
 pkts bytes target     prot opt in     out     source               destination
 7935  617K KUBE-SERVICES  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service portals */

Chain INPUT (policy ACCEPT 2 packets, 627 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 831 packets, 50719 bytes)
 pkts bytes target     prot opt in     out     source               destination
 366K   22M KUBE-SERVICES  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service portals */

Chain POSTROUTING (policy ACCEPT 827 packets, 50479 bytes)
 pkts bytes target     prot opt in     out     source               destination
 498K   31M KUBE-POSTROUTING  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes postrouting rules */
 498K   31M LIBVIRT_PRT  all  --  *      *       0.0.0.0/0            0.0.0.0/0
76716 4660K RETURN     all  --  *      *       10.244.0.0/16        10.244.0.0/16
 1272 76464 MASQUERADE  all  --  *      *       10.244.0.0/16       !224.0.0.0/4          random-fully
    0     0 RETURN     all  --  *      *      !10.244.0.0/16        10.244.0.0/24
    0     0 MASQUERADE  all  --  *      *      !10.244.0.0/16        10.244.0.0/16        random-fully

Chain KUBE-KUBELET-CANARY (0 references)
 pkts bytes target     prot opt in     out     source               destination

Chain KUBE-MARK-DROP (0 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            MARK or 0x8000

Chain KUBE-MARK-MASQ (22 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            MARK or 0x4000

Chain KUBE-NODEPORTS (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-SVC-I54GZH7ZC463PLQ6  tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ tcp dpt:30001

Chain KUBE-POSTROUTING (1 references)
 pkts bytes target     prot opt in     out     source               destination
  831 50719 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match ! 0x4000/0x4000
    0     0 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            MARK xor 0x4000
    0     0 MASQUERADE  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service traffic requiring SNAT */ random-fully

Chain KUBE-PROXY-CANARY (0 references)
 pkts bytes target     prot opt in     out     source               destination

Chain KUBE-SEP-6E7XQMQ4RAYOWTTM (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.0.3           0.0.0.0/0            /* kube-system/kube-dns:dns */
    0     0 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns */ udp to:10.244.0.3:53

Chain KUBE-SEP-DCC4L7OVPB5CTGHJ (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.7           0.0.0.0/0            /* default/nodeportservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ tcp to:10.244.1.7:80

Chain KUBE-SEP-IT2ZTR26TO4XFPTO (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.0.2           0.0.0.0/0            /* kube-system/kube-dns:dns-tcp */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns-tcp */ tcp to:10.244.0.2:53

Chain KUBE-SEP-IWJCVIOI5A2IP7ND (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.7           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.7:80
Chain KUBE-SEP-N4G2XR5TDX7PQE7P (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.0.2           0.0.0.0/0            /* kube-system/kube-dns:metrics */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:metrics */ tcp to:10.244.0.2:9153

Chain KUBE-SEP-QXNCXG4LOSA2TZAQ (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.8           0.0.0.0/0            /* default/nodeportservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ tcp to:10.244.1.8:80

Chain KUBE-SEP-TME5DB4L4HUUFKUT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.8           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.8:80

Chain KUBE-SEP-UKJZAFLCNEDPWYJU (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.6           0.0.0.0/0            /* default/nodeportservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ tcp to:10.244.1.6:80

Chain KUBE-SEP-V3FKGIPPTFTFWTFR (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.6           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.6:80

Chain KUBE-SEP-XQLVMUS2B5RDCPB3 (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.5           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.5:80

Chain KUBE-SEP-XWFENG4R272LDJ7S (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       192.168.1.13         0.0.0.0/0            /* default/kubernetes:https */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/kubernetes:https */ tcp to:192.168.1.13:6443

Chain KUBE-SEP-YIL6JZP7A3QYXJU2 (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.0.2           0.0.0.0/0            /* kube-system/kube-dns:dns */
    0     0 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns */ udp to:10.244.0.2:53

Chain KUBE-SEP-ZCTTZSGQSZOC54R4 (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.5           0.0.0.0/0            /* default/nodeportservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ tcp to:10.244.1.5:80

Chain KUBE-SEP-ZP3FB6NMPNCO4VBJ (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.0.3           0.0.0.0/0            /* kube-system/kube-dns:metrics */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:metrics */ tcp to:10.244.0.3:9153

Chain KUBE-SEP-ZXMNUKOKXUTL2MK2 (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.0.3           0.0.0.0/0            /* kube-system/kube-dns:dns-tcp */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns-tcp */ tcp to:10.244.0.3:53
Chain KUBE-SERVICES (2 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-SVC-NPX46M4PTMTKRN6Y  tcp  --  *      *       0.0.0.0/0            10.96.0.1            /* default/kubernetes:https cluster IP */ tcp dpt:443
    0     0 KUBE-SVC-TCOU7JCQXEZGVUNU  udp  --  *      *       0.0.0.0/0            10.96.0.10           /* kube-system/kube-dns:dns cluster IP */ udp dpt:53
    0     0 KUBE-SVC-ERIFXISQEP7F7OF4  tcp  --  *      *       0.0.0.0/0            10.96.0.10           /* kube-system/kube-dns:dns-tcp cluster IP */ tcp dpt:53
    0     0 KUBE-SVC-JD5MR3NA4I4DYORP  tcp  --  *      *       0.0.0.0/0            10.96.0.10           /* kube-system/kube-dns:metrics cluster IP */ tcp dpt:9153
    0     0 KUBE-SVC-IAEKQ2XJ6CG3CMAV  tcp  --  *      *       0.0.0.0/0            10.110.244.138       /* default/clusteripservice cluster IP */ tcp dpt:8080
    0     0 KUBE-SVC-I54GZH7ZC463PLQ6  tcp  --  *      *       0.0.0.0/0            10.98.126.255        /* default/nodeportservice cluster IP */ tcp dpt:8080
  636 38560 KUBE-NODEPORTS  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service nodeports; NOTE: this must be the last rule in this chain */ ADDRTYPE match dst-type LOCAL

Chain KUBE-SVC-ERIFXISQEP7F7OF4 (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  tcp  --  *      *      !10.244.0.0/16        10.96.0.10           /* kube-system/kube-dns:dns-tcp cluster IP */ tcp dpt:53
    0     0 KUBE-SEP-IT2ZTR26TO4XFPTO  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns-tcp */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-ZXMNUKOKXUTL2MK2  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns-tcp */

Chain KUBE-SVC-I54GZH7ZC463PLQ6 (2 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  tcp  --  *      *      !10.244.0.0/16        10.98.126.255        /* default/nodeportservice cluster IP */ tcp dpt:8080
    0     0 KUBE-MARK-MASQ  tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ tcp dpt:30001
    0     0 KUBE-SEP-ZCTTZSGQSZOC54R4  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ statistic mode random probability 0.25000000000
    0     0 KUBE-SEP-UKJZAFLCNEDPWYJU  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ statistic mode random probability 0.33333333349
    0     0 KUBE-SEP-DCC4L7OVPB5CTGHJ  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-QXNCXG4LOSA2TZAQ  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/nodeportservice */

Chain KUBE-SVC-IAEKQ2XJ6CG3CMAV (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  tcp  --  *      *      !10.244.0.0/16        10.110.244.138       /* default/clusteripservice cluster IP */ tcp dpt:8080
    0     0 KUBE-SEP-XQLVMUS2B5RDCPB3  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ statistic mode random probability 0.25000000000
    0     0 KUBE-SEP-V3FKGIPPTFTFWTFR  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ statistic mode random probability 0.33333333349
    0     0 KUBE-SEP-IWJCVIOI5A2IP7ND  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-TME5DB4L4HUUFKUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */

Chain KUBE-SVC-JD5MR3NA4I4DYORP (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  tcp  --  *      *      !10.244.0.0/16        10.96.0.10           /* kube-system/kube-dns:metrics cluster IP */ tcp dpt:9153
    0     0 KUBE-SEP-N4G2XR5TDX7PQE7P  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:metrics */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-ZP3FB6NMPNCO4VBJ  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:metrics */

Chain KUBE-SVC-NPX46M4PTMTKRN6Y (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  tcp  --  *      *      !10.244.0.0/16        10.96.0.1            /* default/kubernetes:https cluster IP */ tcp dpt:443
    0     0 KUBE-SEP-XWFENG4R272LDJ7S  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/kubernetes:https */

Chain KUBE-SVC-TCOU7JCQXEZGVUNU (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  udp  --  *      *      !10.244.0.0/16        10.96.0.10           /* kube-system/kube-dns:dns cluster IP */ udp dpt:53
    0     0 KUBE-SEP-YIL6JZP7A3QYXJU2  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-6E7XQMQ4RAYOWTTM  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kube-dns:dns */

Chain LIBVIRT_PRT (1 references)
 pkts bytes target     prot opt in     out     source               destination
   80  5815 RETURN     all  --  *      *       192.168.122.0/24     224.0.0.0/24
    0     0 RETURN     all  --  *      *       192.168.122.0/24     255.255.255.255
    0     0 MASQUERADE  tcp  --  *      *       192.168.122.0/24    !192.168.122.0/24     masq ports: 1024-65535
    0     0 MASQUERADE  udp  --  *      *       192.168.122.0/24    !192.168.122.0/24     masq ports: 1024-65535
    0     0 MASQUERADE  all  --  *      *       192.168.122.0/24    !192.168.122.0/24
```
```
