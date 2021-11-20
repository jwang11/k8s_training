## Ingress实战
> 本文使用[traefik](https://doc.traefik.io/traefik/) 来配合Kubernetes，实现ingress的功能

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

- 自签名issuer

*`issuer.yml`*
```diff
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-cluster-issuer
spec:
  selfSigned: {}
```
`$ kubectl apply -f issuer.yml`

- 生成certificate

*`certificate.yml`*
```diff
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: mylab-com-cert
spec:
  secretName: mylab-com-cert-secret
  isCA: true
  commonName: '*.mylab.com'
  dnsNames:
    - mylab.com
    - '*.mylab.com'
  issuerRef:
    name: selfsigned-cluster-issuer
    # We can reference ClusterIssuers by changing the kind here.
    # The default value is Issuer (i.e. a locally namespaced Issuer)
    kind: ClusterIssuer
    group: cert-manager.io
```
