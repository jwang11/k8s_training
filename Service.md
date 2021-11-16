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