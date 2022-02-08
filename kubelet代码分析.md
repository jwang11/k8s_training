# Kubelet代码分析
> 在Kubernetes集群中，每个Node节点（又称Minion）上都会启动一个Kubelet服务进行。
> 该进程用于处理Master节点下发到本节点的任务，管理Pod及Pod中的容器。
> 每个Kubelet进程会在API Server上注册节点自身信息，定期向Master节点汇报节点资源的使用情况，并通过cAdvise监控容器和节点资源。


![kubelet功能模块图](kubelet_功能模块图.png)

## 代码入口

Kubelet 的主函数入口在 `cmd/kubelet/kubelet.go`中
```diff
func main() {
	command := app.NewKubeletCommand()

	// kubelet uses a config file and does its own special
	// parsing of flags and that config file. It initializes
	// logging after it is done with that. Therefore it does
	// not use cli.Run like other, simpler commands.
	code := run(command)
	os.Exit(code)
}

func run(command *cobra.Command) int {
	defer logs.FlushLogs()
	rand.Seed(time.Now().UnixNano())

	command.SetGlobalNormalizationFunc(cliflag.WordSepNormalizeFunc)
	if err := command.Execute(); err != nil {
		return 1
	}
	return 0
}
```
