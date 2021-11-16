## Service服务

Kubernetes中定义了一种名为Service的抽象，用于对Pod进行逻辑分组，并定义了分组访问策略。
这一组Pod能够被Service访问，通常通过标签选择器（label selector）来确定是哪些Pod的。
虽然后端Pod可能会发生变化，但前端客户端不需要知道这一点，也不必跟踪后端的变化。通过Service可以解耦这种关联。
除此之外，还可以使用Ingress来发布服务。Ingress并不是某种服务类型，可以充当集群的入口。
Ingress支持将路由规则合并到单个资源中，在同一IP地址下发布多个服务。

### CluserIP Service
