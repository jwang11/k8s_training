# K8S Informer进阶
>> K8s中有几十种类型的资源，如何能让 K8s 内部以及外部用户方便、高效的获取某类资源的变化，就是Informer的工作。
>> 在k8s_informer机制一文，介绍了informer的大致工作流程，本文是该部分进阶学习，重点在Reflector，DeltaFifo和Indexer。

## Reflector

Reflector 的主要职责是从 apiserver 拉取并持续监听 (ListAndWatch) 相关资源类型的增删改(Add/Update/Delete) 事件, 存储在由 DeltaFIFO 实现的本地缓存(local Store) 中.
首先看一下 Reflector 结构体定义:
```diff
// staging/src/k8s.io/client-go/tools/cache/reflector.go
type Reflector struct {
    // 通过 file:line 唯一标识的 name
    name string

    // 下面三个为了确认类型
    expectedTypeName string
    expectedType     reflect.Type
    expectedGVK      *schema.GroupVersionKind

    // 存储 interface: 具体由 DeltaFIFO 实现存储
    store Store
    // 用来从 apiserver 拉取全量和增量资源
    listerWatcher ListerWatcher

    // 下面两个用来做失败重试
    backoffManager         wait.BackoffManager
    initConnBackoffManager wait.BackoffManager

    // informer 使用者重新同步的周期
    resyncPeriod time.Duration
    // 判断是否满足可以重新同步的条件
    ShouldResync func() bool

    clock clock.Clock

    // 是否要进行分页 List
    paginatedResult bool

    // 最后同步的资源版本号，以此为依据，watch 只会监听大于此值的资源
    lastSyncResourceVersion string
    // 最后同步的资源版本号是否可用
    isLastSyncResourceVersionUnavailable bool
    // 加把锁控制版本号
    lastSyncResourceVersionMutex sync.RWMutex

    // 每页大小
    WatchListPageSize int64
    // watch 失败回调 handler
    watchErrorHandler WatchErrorHandler
}
```

