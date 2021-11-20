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

- 生成dashboard的Authentication

```diff
$ bash <<'EOF'
   
# Change these credentials to your own
export TRAEFIK_UI_USER=admin
export TRAEFIK_UI_PASS=dashboard
export DESTINATION_FOLDER=${HOME}/temp/traefik-ui-creds
   
# Backup credentials to local files (in case you'll forget them later on)
mkdir -p ${DESTINATION_FOLDER}
echo $TRAEFIK_UI_USER >> ${DESTINATION_FOLDER}/traefik-ui-user.txt
echo $TRAEFIK_UI_PASS >> ${DESTINATION_FOLDER}/traefik-ui-pass.txt
   
htpasswd -Bbn ${TRAEFIK_UI_USER} ${TRAEFIK_UI_PASS} \
    > ${DESTINATION_FOLDER}/htpasswd
   
unset TRAEFIK_UI_USER TRAEFIK_UI_PASS DESTINATION_FOLDER
   
EOF

$ kubectl create secret generic traefik-dashboard-auth-secret \
   --from-file=$HOME/temp/traefik-ui-creds/htpasswd \
   --namespace traefik
```

- Dashboard

*`ingress_route.yml`*
```diff
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: traefik-dashboard-auth
spec:
  basicAuth:
    secret: traefik-dashboard-auth-secret
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: traefik-dashboard
spec:
  entryPoints:
    - websecure
  routes:
    - kind: Rule
      match: Host(`traefik.mylab.com`) && (PathPrefix(`/api`) || PathPrefix(`/dashboard`))
      services:
        - name: api@internal
          kind: TraefikService
      middlewares:
        - name: traefik-dashboard-auth # Referencing the BasicAuth middleware
  tls:
    secretName: mylab-com-cert-secret
```
`$ kubectl apply -f ingress_route.yml`

- 测试dashboard

```diff
$ kubectl get svc
NAME                   TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
cert-manager           ClusterIP      10.101.255.31   <none>        9402/TCP                     153m
cert-manager-webhook   ClusterIP      10.97.26.23     <none>        443/TCP                      153m
kubernetes             ClusterIP      10.96.0.1       <none>        443/TCP                      4d6h
traefik                LoadBalancer   10.108.184.3    <pending>     80:30690/TCP,443:32714/TCP   23h

+ traefik dashboard可以通过nodeip:30690（http）/32714(https)，或者clusterIP 10.108.184.3:80来访问

$ curl -H Host:traefik.mylab.com http://10.108.184.3/dashboard/
```
