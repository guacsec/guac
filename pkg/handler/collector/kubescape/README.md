# Kubescape GUAC Collector

This collector connects to the Kubernetes api server and gets either
"sbomsyfts" or "sbomsyftfiltereds" objects, extracts the SBOMs from the
objects, then ingests them into GUAC.

Either a "get" is used if polling is off, or a "watch" is used if polling is
enabled. The collector is expected to be running in cluster for authentication,
and is expected to be run with a service account that has a role binding to
get/watch those objects.

## Usage

Get regular sboms once:

```bash
$ guacone collect kubescape
```

Watch filtered sboms from "alternate" namespace:

```bash
$ guacone collect kubescape --poll --kubescape-filtered --kubescape-namespace=alternate
```

## ClusterRole

[RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

Needs to contain:

```yaml
- apiGroups:
  - spdx.softwarecomposition.kubescape.io
  resources:
  - sbomsyfts
  - sbomsyftfiltereds
  verbs:
  - get
  - watch
  - list
```

## TODO

- Get VEX objects from Kubescape
- Add options to get list existing of sboms on start of poll/watch.
- Update the GUAC Helm chart to optionally deploy this collector.
  - https://github.com/kusaridev/helm-charts/tree/main/charts/guac
- Add an example to https://docs.guac.sh/
