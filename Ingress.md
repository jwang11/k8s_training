## Ingress实战
> 本文使用traefik https://doc.traefik.io/traefik/ 来配合Kubernetes，实现ingress的功能

### Traefik安装和配置

- 利用helm直接安装traefik
```diff

$ helm repo add traefik https://helm.traefik.io/traefik
$ helm repo update
$ helm install traefik traefik/traefik

- 可选安装cert-manager（如果走https）
$ helm repo add jetstack https://charts.jetstack.io
$ helm repo update
$ helm search repo cert-manager
$ helm install traefik traefik/traefik

$ helm upgrade --install cert-manager \
    jetstack/cert-manager \
    --set installCRDs=true
```
