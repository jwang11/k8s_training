## K8S Service服务

    K8S中定义了一种名为Service的抽象，用于对Pod进行逻辑分组，并定义了网络分组访问策略。(注意，service不管理Pod，它是一种网络服务发现的能力）
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

### 1. ClusterIP服务
- 通过deployment创建一组pods，标签example=forservice

*`example_deployment.yml`*
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

*`example_pod.yml`*
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

执行后，现在有4个标签为example=forservice的Pods
```diff
$ kubectl apply -f example_deployment.yml,example_pod.yml

+ 等一会儿，让Pod全部起来

$ kubectl get pods
NAME                              READY   STATUS    RESTARTS   AGE
examplepod                        1/1     Running   0          88m
exampleservice-78d6997f86-n7wz6   1/1     Running   0          106m
exampleservice-78d6997f86-s245p   1/1     Running   0          106m
exampleservice-78d6997f86-wsjsl   1/1     Running   0          106m
```

- 创建ClusterIP服务，关联到标签为example=forservice的Pods

*`clusterip_service.yml`*
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
$ kubectl appy -f clusterip_service.yml
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

### 2. Nodeport服务

    通过NodePort发布的方式基于通过ClusterIP发布的方式，先生成一个ClusterIP，然后将这个虚拟IP地址及端口映射到各个集群机器（即Master和Node）的指定端口上，这样，Kubernetes集群外部的机器就可以通过“NodeIP:端口”方式访问Service。之前已经提到过，ClusterIP本身已经提供了负载均衡功能，所以在NodePort模式下，不管访问的是集群中的哪台机器，效果都是一模一样的。也就是说，都先由某台机器通过映射关系转发到ClusterIP，然后由ClusterIP通过比例随机算法转发到对应Pod。

- 创建一个nodeport service

*`nodeport_service.yml`*
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

- 测试服务
```diff
$ kubectl get service -o wide
NAME               TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE    SELECTOR
...
nodeportservice    NodePort    10.98.126.255    <none>        8080:30001/TCP   103m   example=forservice
...

+ Node的IP是192.168.1.10，NodePort是30001

$ curl 192.168.1.10:30001
<p>The host is exampleservice-78d6997f86-s245p</p>
$ curl 192.168.1.10:30001
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 192.168.1.10:30001
<p>The host is pod_example</p>
$ curl 192.168.1.10:30001
<p>The host is pod_example</p>
$ curl 192.168.1.10:30001
<p>The host is exampleservice-78d6997f86-s245p</p>
$ curl 192.168.1.10:30001
<p>The host is exampleservice-78d6997f86-s245p</p>
$ curl 192.168.1.10:30001
<p>The host is exampleservice-78d6997f86-n7wz6</p>
$ curl 192.168.1.10:30001
<p>The host is exampleservice-78d6997f86-wsjsl</p>
$ curl 192.168.1.10:30001
<p>The host is pod_example</p>
```

### 3. Headless服务
    无头Service（headless service）是一种特殊的Service类型。通过无头Service发布，不会分配任何ClusterIP地址，也不通过kube-proxy进行反向代理和负载均衡。无头Service是通过DNS提供稳定的网络ID来进行访问的，DNS会将无头Service的后端直接解析为Pod的IP地址列表，通过标签选择器将后端的Pod列表返回给调用的客户端。这种类型的Service只能在集群内的Pod中访问，集群内的机器（即Master和Node）无法直接访问，集群外的机器也无法访问。

因为无头Service不提供负载均衡功能，所以开发人员可以自己控制负载均衡策略，降低与Kubernetes系统的耦合性。无头Service主要供StatefulSet使用。

- 创建Headless服务

***`headless_service.yml`***
```diff
kind: Service
apiVersion: v1
metadata:
  name: headlessservice
spec:
  selector:
    example: forservice
  clusterIP: None
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 80
  type: ClusterIP
```

查看service
```diff
$ kubectl apply -f headless_service.yml

$ kubectl get service -o wide
NAME               TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE    SELECTOR
headlessservice    ClusterIP   None             <none>        8080/TCP         15h    example=forservice
```

    由于这个Service无法由集群内外的机器直接访问，因此只能由Pod访问，而且需要通过DNS形式进行访问。具体访问形式为{ServiceName}.{Namespace}.svc.{ClusterDomain}，其中svc是Service的缩写（固定格式）；ClusterDomain表示集群域，本例中默认的集群域为cluster.local；前面两段文字则是根据Service定义决定的，这个例子中ServiceName为exampleheadlessservice，而Namespace没有在yml文件中指定，默认值为Default。

- 创建test pod来测试Headless

***`test_pod.yml`***
```diff
apiVersion: v1
kind: Pod
metadata:
  name: testheadlessservice
spec:
  containers:
  - name: testcontainer
    image: docker.io/appropriate/curl
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c']
    args: ['echo "test pod for headless service!";sleep 3600']
```
该Pod是一种工具箱，里面存放了一些测试网络和DNS使用的工具（例如，curl和nslookup等），正好用于测试现在的Service。执行sleep 3600命令，可让该容器长期处于运行状态。

```diff
- 运行test pod
$ kubectl apply -ff test_pod.yml

- 进入test pod
$ kubectl exec -ti testheadlessservice -- /bin/sh
/ # nslookup headlessservice.default.svc.cluster.local
Name:      headlessservice.default.svc.cluster.local
Address 1: 10.244.1.12 10-244-1-12.headlessservice.default.svc.cluster.local
Address 2: 10.244.1.10 10-244-1-10.clusteripservice.default.svc.cluster.local
Address 3: 10.244.1.11 10-244-1-11.headlessservice.default.svc.cluster.local

- 访问service域名
/ # curl headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-hcfrr</p>
/ # curl headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-m9fnl</p>
/ # curl headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-m9fnl</p>
/ # curl headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-hcfrr</p>
/ # curl headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-6sf8v</p>

- 访问pod域名
/ # curl 10-244-1-10.clusteripservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-6sf8v</p>
/ # curl 10-244-1-12.headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-m9fnl</p>
/ # curl 10-244-1-11.headlessservice.default.svc.cluster.local
<p>The host is exampleservice-78d6997f86-hcfrr</p>
```
    除了直接调用该域名访问服务之外，还可以通过解析域名并根据自定义需求来决定具体要访问哪个Pod的ID地址。
这种方式更适用于由StatefulSet产生的有状态Pod。


### 4. ExternalName服务
    ExternalName是将外部服务引入进来，通过一定格式映射到Kubernetes集群，从而为集群内部提供服务。也就是说，ExternalName类型的Service没有选择器，也没有定义任何的端口和端点。相反，对于运行在集群外部的服务，通过返回外部服务别名这种方式来提供服务。

- 创建ExternalName服务

***`externalname_service.yml`***
```diff
kind: Service
apiVersion: v1
metadata:
  name: externalnameservice
spec:
  type: ExternalName
  externalName: www.baidu.com
```

检查Service
```diff
$ kubectl get svc
NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP     PORT(S)          AGE
externalnameservice   ExternalName   <none>           www.baidu.com   <none>           64s

- 登录进test_pod
$ kubectl exec -ti testheadlessservice -- /bin/sh
/ # nslookup externalnameservice.default.svc.cluster.local
nslookup: can't resolve '(null)': Name does not resolve

Name:      externalnameservice.default.svc.cluster.local
Address 1: 180.101.49.11
Address 2: 180.101.49.12

- 访问百度这两个反向代理
$ curl 180.101.49.11
<html>
<head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<style data-for="result" id="css_result">
body{color:#333;background:#fff;padding:6px 0 0;margin:0;position:relative;min-width:900px}body,
th,td,.p1,.p2{font-family:arial}p,form,ol,ul,li,dl,dt,dd,h3{margin:0;padding:0;list-style:none}i
nput{padding-top:0;padding-bottom:0;-moz-box-sizing:border-box;-webkit-box-sizing:border-box;box
-sizing:border-box}table,img{border:0}td{font-size:9pt;line-height:18px}
```

### 5. 其它Service配置方式

- Service + Endpoint灵活关联

***`noselector_service.yml`***
```
kind: Service
apiVersion: v1
metadata:
  name: noselectorservice
spec:
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 80
```

检查服务
```diff
$ kubectl apply -f noselector_service.yml
$ kubectl get service
NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP     PORT(S)          AGE
noselectorservice     ClusterIP      10.105.180.157   <none>          8080/TCP         8s
```

配置Endpoints

***`example_endpoint.yml`***
```diff
kind: Endpoints
apiVersion: v1
metadata:
+ 注意，这里endpoint name和service name保持一致，就能够被关联到
  name: noselectorservice
subsets:
  - addresses:
      - ip: 10.244.1.11
    ports:
      - port: 80
```

测试
```diff
$ kubectl apply -f example_endpoint.yml

- 访问clusterIP，就关联到endpoint里的IP
$ curl 10.105.180.157:8080
<p>The host is exampleservice-78d6997f86-hcfrr</p>
```

- ExternalIP发布服务

***`externalip_service.yml`***
```diff
kind: Service
apiVersion: v1
metadata:
  name: externalipservice
spec:
  selector:
    example: forservice
  ports:
    - protocol: TCP
      port: 8081
      targetPort: 80
  externalIPs:
    - 192.168.1.13
```

    检查服务，和ClusterIP服务相比，多了一个EXTERNAL-IP字段。
这个Service其实就是简单的ClusterIP Service，Pod端口为80，而向外映射的端口为8081，这个端口会同时映射到ClusterIP和externalIP。
我们设置的外部IP地址为192.168.1.13，集群外的机器可以通过这个地址访问集群内的服务。
```diff
$ kubectl get svc
NAME                  TYPE           CLUSTER-IP       EXTERNAL-IP     PORT(S)          AGE
clusteripservice      ClusterIP      10.110.244.138   <none>          8080/TCP         21h
externalipservice     ClusterIP      10.100.171.122   192.168.1.13    8081/TCP         2m45s

- 测试从ExternalIP访问
$ curl 192.168.1.13:8081
<p>The host is exampleservice-78d6997f86-hcfrr</p>
$ curl 192.168.1.13:8081
<p>The host is exampleservice-78d6997f86-6sf8v</p>
$ curl 192.168.1.13:8081
<p>The host is pod_example</p>

```


### 6. Ingress
    要将Kubernetes集群内的服务发布到集群外来使用，通常的办法是配置NodePort或LoadBalancer的Service，或者给Service配置ExternalIP，或者通过Pod模板中的HostPort进行配置等。但这些方式都存在比较严重的问题。它们几乎都是通过节点端口形式向外暴露服务的，Service一旦变多，每个节点上开启的端口也会变多。这样不仅维护起来相当复杂，安全性还会大大降低。Ingress可以避免这个问题，除了Ingress自身的服务需要向外发布之外，其他服务不必使用节点端口形式向外发布。由Ingress接收外部请求，然后按照域名配置转发给各个后端服务。
   在使用Ingress时一般会涉及3个组件
- Ingress Controller控制器：实质上是监控器。它不断地与API Server进行交互，实时地感知后端Service、Pod等的变化情况，比如新增和减少Pod、增加与减少Service等。当得到这些变化信息后，Ingress控制器再结合Ingress生成配置，然后更新反向代理负载均衡器并刷新其配置，以达到服务发现的作用。
- 反向代理（Reverse Proxy）负载均衡器：其实它类似于Nginx、Apache的应用。在集群中可以使用Deployment、DaemonSet等控制器自由部署反向代理负载均衡器。
- Ingress route路由：定义访问规则。假如某个域名对应某个Service，或者某个域名下的子路径对应某个Service，那么当某个域名的请求或子路径的请求进来时，就把请求转发给对应Service。根据这个规则，Ingress控制器会将访问规则动态写入负载均衡器配置中，从而实现整体的服务发现和负载均衡。

Ingress控制器不会随着Kubernetes一起安装。如果要让Ingress资源正常运作，需要安装Ingress控制器。可以选择的Ingress控制器种类很多，可根据情况自行选择，参考Ingress实战。
