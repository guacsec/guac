# Deploying GUAC with Helm Chart

This tutorial introduces the full GUAC components deployment and how to deploy
it with [Kusari's GUAC Helm Chart](https://github.com/kusaridev/helm-charts/tree/main/charts/guac).

In case you run into issues with using the helm chart that this document doesn't address, please refer to documentation at [Kusari's GUAC Helm Chart](https://github.com/kusaridev/helm-charts/tree/main/charts/guac).
## Prerequisites

- Kubernetes
  - Deploy one of these for local testing if you don't have a Kubernetes cluster ready:
    - [kind](https://kind.sigs.k8s.io/), [minikube](https://minikube.sigs.k8s.io/docs/start/), [colima](https://github.com/abiosoft/colima)
- [Helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- Docker
- Git

## Deploy GUAC

Add the [kusaridev/helm-charts](https://github.com/kusaridev/helm-charts) repo and search for the guac helm chart.

```bash
helm repo add kusaridev https://kusaridev.github.io/helm-charts
helm repo update

helm search repo kusaridev
NAME            CHART VERSION   APP VERSION     DESCRIPTION                                  
kusaridev/guac  0.1.3           v0.0.1          A Helm chart for deploying GUAC to Kubernetes
```

Deploy the helm chart
```
helm install [RELEASE_NAME] kusaridev/guac

e.g.
helm install guac kusaridev/guac 

NAME: guac
LAST DEPLOYED: Fri Apr 21 22:59:39 2023
NAMESPACE: default
STATUS: deployed
REVISION: 1
```

Verify the pods and services are running once the chart is deployed.
```
kubectl get pod
NAME                                 READY   STATUS    RESTARTS       AGE
collectsub-575ff76c99-wsfdl          1/1     Running   0              108s
depsdev-collector-655db4b49d-btcg9   1/1     Running   3 (88s ago)    108s
graphql-server-74b46ff6bf-hmvh5      1/1     Running   0              108s
guac-nats-0                          3/3     Running   0              108s
guac-nats-box-64df4968d5-gx4hw       1/1     Running   0              108s
ingestor-8cc978c9-xdl9x              1/1     Running   3 (91s ago)    108s
oci-collector-7495cfd4f7-kktfn       1/1     Running   3 (90s ago)    108s
osv-certifier-78ccb89845-5jcqh       1/1     Running   2 (103s ago)   108s
visualizer-7f4dc7cbd6-xxq7f          1/1     Running   0              108s

kubectl get svc
NAME             TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)                                                 AGE
collectsub       ClusterIP   10.96.190.54   <none>        2782/TCP                                                105s
graphql-server   ClusterIP   10.96.136.46   <none>        8080/TCP                                                105s
guac-nats        ClusterIP   None           <none>        4222/TCP,6222/TCP,8222/TCP,7777/TCP,7422/TCP,7522/TCP   105s
kubernetes       ClusterIP   10.96.0.1      <none>        443/TCP                                                 10d
visualizer       ClusterIP   10.96.219.45   <none>        3000/TCP                                                105s
```

#### Expose services via kubectl port-forward
The full GUAC deployment is now running. You may use ```kubectl port-forward``` to gain access to respective services.

```
kubectl port-forward svc/graphql-server 8080:8080 &
kubectl port-forward svc/visualizer 3000:3000 &
```

The GraphQL server service is listening on port `8080`. You may visit [http://localhost:8080](http://localhost:8080) to see the GraphQL playground. GraphQL queries are served at the `/query` endpoint.
You may visit [http://localhost:3000](http://localhost:3000) to see the Visualizer.

If there is a need to access NATS and CollectSub service, e.g. you're running the ```guaccollect``` command, run
```
kubectl port-forward svc/guac-nats 4222:4222 &
kubectl port-forward svc/collectsub 2782:2782 &
```

NATS is listening on port `4222`, this is where the collectors will to connect to push any docs they find. The GUAC `guaccollect` command defaults to `nats://127.0.0.1:4222` for the NATS address, so this will work automatically.


## Start Ingesting Data

Now you can run the `guacone files` ingestion command to load data into your
GUAC deployment. For example we can ingest the sample `guacsec/guac-data` data. However,
you may ingest what you wish to here instead.

#### Clone the sample GUAC data

```bash
git clone https://github.com/guacsec/guac-data.git

cd guac-data
```
The rest of the tutorial will assume you are in the ```guac-data``` directory

#### Pull the GUAC container image
The ```guacone``` binary is packaged in the guac container image. Let's pull it so we can run the ingestion.

```bash
docker pull ghcr.io/kusaridev/guac:v0.0.1-beta.5 
```
You may pull newer versions of the guac container as they became available.

#### Following the logs
Optionally, in a separate terminal, you may follow the logs of all the services to see what's going on behind the scene as you ingest the sample data.
```
kubectl logs -l app.kubernetes.io/part-of=guac -f --max-log-requests 8
...
{"level":"info","ts":1682341513.016985,"caller":"cmd/root.go:98","msg":"Using config file: /workspace/guac.yaml"}
{"level":"info","ts":1682341513.0295882,"caller":"server/server.go:87","msg":"server listening at [::]:2782"}
{"level":"info","ts":1682341512.3418722,"caller":"cmd/root.go:115","msg":"Using config file: /workspace/guac.yaml"}
{"level":"info","ts":1682341512.349486,"caller":"cmd/server.go:64","msg":"connect to http://localhost:8080/ for GraphQL playground"}
{"level":"info","ts":1682341512.3497534,"caller":"cmd/server.go:68","msg":"starting server"}
{"level":"info","ts":1682341530.6957734,"caller":"cmd/root.go:102","msg":"Using config file: /workspace/guac.yaml"}
{"level":"info","ts":1682341530.7744906,"caller":"cmd/osv.go:118","msg":"certifier ended gracefully"}
{"level":"info","ts":1682341555.712654,"caller":"cmd/root.go:88","msg":"Using config file: /workspace/guac.yaml"}
{"level":"info","ts":1682341555.7592425,"caller":"emitter/nats_emitter.go:121","msg":"creating stream \"DOCUMENTS\" and subjects \"DOCUMENTS.*\""}
{"level":"info","ts":1682341559.5807755,"caller":"cmd/root.go:92","msg":"Using config file: /workspace/guac.yaml"}
ready - started server on 0.0.0.0:3000, url: http://localhost:3000
warn  - You have enabled experimental feature (appDir) in next.config.js.
info  - Thank you for testing `appDir` please leave your feedback at https://nextjs.link/app-feedback
warn  - Experimental features are not covered by semver, and may cause unexpected or broken application behavior. Use at your own risk.

{"level":"info","ts":1682341559.5920317,"caller":"cmd/root.go:92","msg":"Using config file: /workspace/guac.yaml"}
```

#### Ingesting sample data
We are ingesting the sboms in guac-data/docs dir in this example.
```bash
docker run --rm -v $PWD:/data --entrypoint /cnb/process/guacone  ghcr.io/kusaridev/guac:v0.0.1-beta.5 files /data/docs --gql-endpoint http://host.docker.internal:8080/query
```
This command uses the `/cnb/process/guacone` GUAC binary from the `guac` container - specified via the ```--entrypoint``` flag. The parameters are toward the end of the command after the image name (following docker run's syntax).

Because containers don't have access to the host's localhost by default, we use the `host.docker.internal` hostname to access the port-forward exposed at localhost. The command uses a volume mount to mout `guac-data` into the container for collecting (`-v $PWD:/data`). 

Switch back to the logs terminal and you will soon see that the OSV certifier recognized the new packages and is looking up vulnerability information for them.
```
...
{"level":"info","ts":1682343662.38526,"caller":"cmd/osv.go:111","msg":"[4.73ms] completed doc {Collector:guac Source:guac}"}
{"level":"info","ts":1682343662.385466,"caller":"parser/parser.go:128","msg":"parsing document tree with root type: ITE6VUL"}
{"level":"info","ts":1682343662.385925,"caller":"helpers/assembler.go:34","msg":"assembling CertifyScorecard: 0"}
{"level":"info","ts":1682343662.3859775,"caller":"helpers/assembler.go:39","msg":"assembling IsDependency: 0"}
{"level":"info","ts":1682343662.3861685,"caller":"helpers/assembler.go:44","msg":"assembling IsOccurence: 0"}
{"level":"info","ts":1682343662.3863058,"caller":"helpers/assembler.go:49","msg":"assembling HasSLSA: 0"}
{"level":"info","ts":1682343662.3863401,"caller":"helpers/assembler.go:54","msg":"assembling CertifyVuln: 1"}
{"level":"info","ts":1682343662.390311,"caller":"helpers/assembler.go:59","msg":"assembling IsVuln: 0"}
{"level":"info","ts":1682343662.390399,"caller":"helpers/assembler.go:64","msg":"assembling HasSourceAt: 0"}
{"level":"info","ts":1682343662.3904305,"caller":"helpers/assembler.go:69","msg":"assembling CertifyBad: 0"}
{"level":"info","ts":1682343662.3904605,"caller":"helpers/assembler.go:74","msg":"assembling CertifyGood: 0"}
{"level":"info","ts":1682343662.390515,"caller":"cmd/osv.go:111","msg":"[5.174708ms] completed doc {Collector:guac Source:guac}"}
...
```

**Note** - in case you run into errors, double check that you've run the [port-forward commands](#expose-services-via-kubectl-port-forward) previously to expose other services at localhost and that you're running the ingestion command at in the ```guac-data``` dir.


## Query GraphQL Endpoint

You may now query the GraphQL endpoint to ensure the data is ingested, and
everything is running.

```bash
curl 'http://localhost:8080/query' -s -X POST -H 'content-type: application/json' \
  --data '{
    "query": "{ packages(pkgSpec: {}) { type } }"
  }' | jq
```

You should see the types of all the packages ingested

```json
{
  "data": {
    "packages": [
      {
        "type": "oci"
      },
...
```

Congratulations, you are now running a full GUAC deployment!

## What is running?

The output of `kubectl get pod` shows the different running services. Here is a brief descriptions of what they are:

- **GraphQL Server**: Serving GUAC GraphQL queries and storing the data. As the
  in-memory backend is used, no separate backend is needed behind the server.

- **Collector-Subscriber**: This component helps communicate to the collectors
  when additional information is needed.

- **Ingestor**: The ingestor listens for things to ingest through NATS, then
  pushes to the GraphQL Server. The ingestor also runs the assembler and parser
  internally.

- **Image Collector**: This collector can pull OCI image metadata (SBOMs and
  attestations) from registries for further inspection.

- **Deps.dev Collector**: This collector gathers further information from
  [Deps.dev](https://deps.dev/) for supported packages.

- **OSV Certifier**: This certifier gathers OSV vulnerability information from
  [osv.dev](https://osv.dev/) about packages.

- **NATS**: NATS is used for communication between the GUAC components.

## Next steps

The GUAC Helm Chart deployment is suitable to leave running in an environment that is accessible to you for further GUAC ingestion, discovery, analysis, and evaluation. Keep in mind that the in-memory backend is not persistent.

Explore the types of collectors available in the `guaccollect` binary and see what will work for your build, ingestion, and SBOM workflow. These collectors can be run as another service that watches a location for new documents to ingest.
