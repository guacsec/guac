allow_k8s_contexts('kind-kind')
analytics_settings(enable=False)

load('ext://helm_remote', 'helm_remote')
helm_remote('nats', repo_url='https://nats-io.github.io/k8s/helm/charts/', repo_name='nats', version='0.19.17', values='k8s/tilt-nats-values.yaml')

custom_build('local-organic-guac', "export GUAC_IMAGE=\"$EXPECTED_IMAGE\" && make container", deps='pkg/', tag="latest")
k8s_yaml('k8s/k8s.yaml')

k8s_resource(
    workload='guac-collectsub',
    resource_deps=['nats']
)

k8s_resource(
   workload='guac-graphql',
   port_forwards=[
      port_forward(8080, 8080, name='graphql')
   ]
)
