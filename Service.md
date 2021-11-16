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
...
Chain KUBE-SEP-IWJCVIOI5A2IP7ND (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.7           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.7:80

Chain KUBE-SEP-TME5DB4L4HUUFKUT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.8           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.8:80

Chain KUBE-SEP-V3FKGIPPTFTFWTFR (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.6           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.6:80

- 步骤3， 这里出现具体IP地址
Chain KUBE-SEP-XQLVMUS2B5RDCPB3 (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       10.244.1.5           0.0.0.0/0            /* default/clusteripservice */
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ tcp to:10.244.1.5:80

- 步骤1，KUBE-SERVICES转到KUBE-SVC-IAEKQ2XJ6CG3CMAV
Chain KUBE-SERVICES (2 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-SVC-IAEKQ2XJ6CG3CMAV  tcp  --  *      *       0.0.0.0/0            10.110.244.138       /* default/clusteripservice cluster IP */ tcp dpt:8080


- 步骤2，KUBE-SVC-IAEKQ2XJ6CG3CMAV按照random probability模式做LB访问，如KUBE-SEP-XQLVMUS2B5RDCPB3有20%几率
Chain KUBE-SVC-IAEKQ2XJ6CG3CMAV (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  tcp  --  *      *      !10.244.0.0/16        10.110.244.138       /* default/clusteripservice cluster IP */ tcp dpt:8080
    0     0 KUBE-SEP-XQLVMUS2B5RDCPB3  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ statistic mode random probability 0.25000000000
    0     0 KUBE-SEP-V3FKGIPPTFTFWTFR  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ statistic mode random probability 0.33333333349
    0     0 KUBE-SEP-IWJCVIOI5A2IP7ND  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */ statistic mode random probability 0.50000000000
    0     0 KUBE-SEP-TME5DB4L4HUUFKUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* default/clusteripservice */
```

### Nodeport服务

通过NodePort发布的方式基于通过ClusterIP发布的方式，先生成一个ClusterIP，然后将这个虚拟IP地址及端口映射到各个集群机器（即Master和Node）的指定端口上，这样，Kubernetes集群外部的机器就可以通过“NodeIP:端口”方式访问Service。之前已经提到过，ClusterIP本身已经提供了负载均衡功能，所以在NodePort模式下，不管访问的是集群中的哪台机器，效果都是一模一样的。也就是说，都先由某台机器通过映射关系转发到ClusterIP，然后由ClusterIP通过比例随机算法转发到对应Pod。

- 创建一个nodeport service

===nodeport_service.yml===
```diff
kind: Service
apiVersion: v1
metadata:
  name: nodeportservice
spec:
  selector:
    example: forservice
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 80
      nodePort: 30001
  type: NodePort
```
