# Istio Ambient Mesh

- Helm Install Istio Ambient Mesh

```bash
#!/bin/bash
# Install Ambient Mesh with Helm Charts


REPO="https://istio-release.storage.googleapis.com/charts"
VERSION=1.20.1
helm_opts="upgrade -i --namespace istio-system --create-namespace --repo ${REPO} --version ${VERSION}"

# base
helm $(echo $helm_opts) istio-base base

# istiod
helm $(echo $helm_opts)  istiod istiod  --values - <<EOF
meshConfig:
  defaultConfig:
    proxyMetadata:
      ISTIO_META_ENABLE_HBONE: "true"
  # Telemetry API is used with ambient instead of EnvoyFilters
  defaultProviders:
    metrics:
    - prometheus
  extensionProviders:
  - name: prometheus
    prometheus: {}
pilot:
  env:
    VERIFY_CERTIFICATE_AT_CLIENT: "true"
    ENABLE_AUTO_SNI: "true"
    PILOT_ENABLE_HBONE: "true"
    CA_TRUSTED_NODE_ACCOUNTS: "istio-system/ztunnel,kube-system/ztunnel"
    PILOT_ENABLE_AMBIENT_CONTROLLERS: "true"
EOF

# istio-cni
helm $(echo $helm_opts)  istio-cni cni  --values - <<EOF
cni:
  logLevel: info
  privileged: true
  ambient:
    enabled: true
EOF

# ztunnel
helm $(echo $helm_opts)  ztunnel ztunnel
```

- Label Namespace for Ambient Mesh

```bash
kubectl label ns default istio.io/dataplane-mode=ambient
```