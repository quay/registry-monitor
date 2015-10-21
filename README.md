registry-monitor
============

Simple go application that monitors a Docker registry by conducting pushes and pulls and reports the status to an HTTP endpoint

Running the monitor
=============================

To run the monitor, execute the following command with the env variable values replaced:

```sh
docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock -e USERNAME=dockerusername -e PASSWORD=dockerpassword -e REGISTRY_HOST=yourregistryhost -e REPOSITORY_NAME=yourregistryhost/namespace/repository -e BASE_IMAGE_ID=somebaseimageid registry-monitor
```

| Env Variable Name     | Description                                                       |
| --------------------- | ----------------------------------------------------------------- |
| USERNAME              | The Docker username for auth                                      |
| PASSWORD              | The Docker password for auth                                      |
| REGISTRY_HOST         | The registry hostname. Example: quay.io                           |
| REPOSITORY_NAME       | The full name of the repository. Example: quay.io/some/repository |
| BASE_IMAGE_ID         | The ID of an image in the repository to use as the base           |
| --------------------- | ----------------------------------------------------------------- |
| Optional Variables                                                                        |
| --------------------- | ----------------------------------------------------------------- |
| DOCKER_HOST           | The docker host to use if not the local Docker instance           |
| CLOUDWATCH_NAMESPACE  | The namespace on AWS CloudWatch to which metrics will be reported |
| AWS_ACCESS_KEY_ID     | The AWS access key for an IAM user with CloudWatch access         |
| AWS_SECRET_ACCESS_KEY | The AWS secret key for an IAM user with CloudWatch access         |
| AWS_DEFAULT_REGION    | The AWS region in which to write the CloudWatch metrics           |

Example:

```sh
docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock -e USERNAME=myuser+robot -e PASSWORD=myrobottoken -e REGISTRY_HOST=quay.io -e REPOSITORY_NAME=quay.io/myuser/monitorrepo -e BASE_IMAGE_ID=4f83eba78c registry-monitor
```

Reading the monitor
=============================
The monitor exposes two HTTP endpoints: `/health` and `/status` on port 8000.

`/status` returns `200 OK` if the pull and push has succeeded within the last monitoring period.
`/health` returns `200 OK` if the monitor binary itself is healthy. If non-200, the binary should be terminated and restarted.


Building new version
===================================
Run the `docker build` command on the local Dockerfile to build a new image:

```
docker build -t registry-monitor .
```

