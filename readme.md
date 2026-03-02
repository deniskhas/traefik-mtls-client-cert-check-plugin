# Traefik mTLS Client Certificate Check Plugin

The traefik-mtls-client-cert-check-plugin is a Traefik middleware plugin that validates client proivded certificate during TLS handshake versus CA provided as k8s secret.

## Installation

```yaml
experimental:
  plugins:
    traefik-mtls-client-cert-check-plugin:
      moduleName: "github.com/deniskhas/traefik-mtls-client-cert-check-plugin"
      version: "v0.0.3"
```

## Usage

```yaml
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: tlsoption
  namespace: demo
spec:
  clientAuth:
    clientAuthType: RequestClientCert
    secretNames:
      - ca-store
```

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: mtls-check
  namespace: demo
spec:
  plugin:
    traefik-mtls-check-plugin:
      secretName: 
      secretNamespace:
      secretKey: ca.crt
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    traefik.ingress.kubernetes.io/router.tls.options: demo-tlsoption@kubernetescrd
    traefik.ingress.kubernetes.io/router.middlewares: demo-mtls-check@kubernetescrd
  name: ingress-traefik
  namespace: demos
spec:
  ingressClassName: traefik
  rules:
```
