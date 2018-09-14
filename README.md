# fargatespawner

Spawns JupyterHub single user notebook servers in Docker containers running in AWS Fargate

## Installation

```
pip install fargatespawner
```

## Configuration

To configure JupyterHub to use FargateSpawner, you can add the following to your `jupyterhub_config.py`.

```python
from fargatespawner import FargateSpawner
c.JupyterHub.spawner_class = FargateSpawner
```

You _must_ also set the following settings on `c.FargateSpawner` in your `jupyterhub_config.py`. None of them are optional.

| Setting | Description | Example |
| --- | --- | --- |
| `aws_region` | The AWS region in which the tasks are launched. | `'eu-west-1'` |
| `aws_host`  | The hostname of the AWS ECS API. Typically, this is of the form `ecs.<aws-region>.amazonaws.com`. | `'ecs.eu-west-1.amazonaws.com'` |
| `aws_access_key_id` | The ID of the AWS access key used to sign the requests to the AWS ECS API. | _ommitted_ |
| `aws_secret_access_key` | The secret part of the AWS access key used to sign the requests to the AWS ECS API .| _ommitted_ |
| `task_cluster_name` | The name of the ECS cluster in which the tasks are launched. | `'jupyerhub-notebooks'` |
| `task_definition_arn` | The family and revision (family:revision) or full ARN of the task definition that runs the notebooks. Typically, this task definition would specify a docker image that builds on one of those from https://github.com/jupyter/docker-stacks. | `'jupyterhub-notebook:7'` |
| `task_security_groups` | The security group(s) associated with the Fargate tasks. These must allow communication to and from the hub/proxy. More information, such as the ports used, is at https://jupyterhub.readthedocs.io/en/stable/getting-started/networking-basics.html. | `['sg-00026fc201a4e374b']` |
| `task_subnets` | The subnets associated with the Fargate tasks. | `['subnet-01fc5f15ac710c012']` } |
| `notebook_port` | The port the notebook servers listen on. | `8888` |
| `notebook_scheme` | The scheme used by the hub and proxy to connect to the notebook servers. At the time of writing `'https'` will not work out of the box. However, users do not connect to the the notebook server directly, and does not, typically, allow incoming connections from the public internet. Instead, users connect to the proxy, which can be configured to listen on HTTPS independently of this setting. There is more information on setting up HTTPS for connections to the proxy at https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html. | `'http'` |
| `notebook_args` | Additional arguments to be passed to `jupyterhub-singleuser` that starts each notebook server. This can be the empty list. | `['--config=notebook_config.py']` |

## Run-time dependencies

The spawner is deliberately written to not have any additional dependencies, beyond those that are required for JupyterHub.
