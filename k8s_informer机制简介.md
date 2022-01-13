# informer简介

## Informer机制流程

- ```Reflector```：通过 Kubernetes API 监控 Kubernetes 的资源类型 采用 List/Watch 机制, 可以 Watch 任何资源包括 CRD 添加 object 对象到 DeltaFIFO 队列，然后 Informer 会从队列里面取数据进行处理。Reflector 会和 apiServer 建立长连接，并使用 ListAndWatch 方法获取并监听某一个资源的变化。List 方法将会获取某个资源的所有实例，Watch 方法则监听资源对象的创建、更新以及删除事件，然后将事件放入到DeltaFIFO Queue中；
- ```DeltaFIFO```：DeltaFIFO是一个先进先出的队列，可以保存资源对象的操作类型；
- ```Informer```：controller 机制的基础，循环处理 object 对象 从 Reflector 取出数据，然后将数据给到 Indexer 去缓存，提供对象事件的 handler 接口，只要给 Informer 添加 ResourceEventHandler 实例的回调函数，去实现 OnAdd(obj interface{})、 OnUpdate(oldObj, newObj interface{}) 和 OnDelete(obj interface{}) 这三个方法，就可以处理好资源的创建、更新和删除操作了。Informer会不断的从 Delta FIFO Queue 中 pop 增量事件，并根据事件的类型来决定新增、更新或者是删除本地缓存；接着Informer 根据事件类型来触发事先注册好的 Event Handler触发回调函数，然后然后将该事件丢到 WorkQueue 这个工作队列中。
- ```Indexer```：用来存储资源对象并自带索引功能的本地存储，提供 object 对象的索引，是线程安全的，缓存对象信息。
- ```workqueue```: 最后轮到Controller从线程安全的Workqueue中取出这个资源的key，进行事件的处理。Controller在处理事件的过程中可能是并行的，有许多个Worker线程不断从Workqueue中取事件并处理。 worker 来业务逻辑通常是计算目前集群的状态和用户希望达到的状态有多大的区别，然后不断的调和处理。Informer/SharedInformer与Worker线程的关系，实际上是一个生产者-消费者关系，利用一个Workqueue将二者分开，既实现了两个部件的解耦，也解决了双方处理速度不一致的问题。
