registry-monitor
============

Simple go application that monitors a Docker registry by conducting pushes and pulls and reports the status to an HTTP endpoint.

Running the monitor
=============================

To run the monitor, execute the following command with the flag values replaced:

| Flag Name             | Description                                                       |
| --------------------- | ----------------------------------------------------------------- |
| username              | The registry username for auth                                    |
| password              | The registry password for auth                                    |
| registry-host         | The registry hostname. Example: quay.io                           |
| repository            | The full name of the repository. Example: quay.io/some/repository |
| base-image-id         | The Docker V1 ID of an image in the repository to use as the base |

```sh
./registry-monitor -username=USERNAME -password=PASSWORD -registry-host=REGISTRYHOST -repository=registryname/some/repository -base-layer-id=DOCKERV1ID
```

The monitor can also be run itself via Docker:

```sh
docker run --privileged -e UNDER_DOCKER=true -v /var/run/docker.sock:/var/run/docker.sock -p 8000:8000 registry-monitor -username=USERNAME -password=PASSWORD -registry-host=REGISTRYHOST -repository=registryname/some/repository -base-layer-id=DOCKERV1ID
```

Docker Example:

```sh
docker run --privileged -e UNDER_DOCKER=true -v /var/run/docker.sock:/var/run/docker.sock -p 8000:8000 registry-monitor -username=myuser+robot -password=myrobottoken -registry-host=quay.io -repository=quay.io/myuser/monitorrepo -base-layer-id=4f83eba78c
```

Reading the monitor
=============================
The monitor exposes three HTTP endpoints on port 8000:

`/status` returns `200 OK` if the pull and push has succeeded within the last monitoring period.
`/health` returns `200 OK` if the monitor binary itself is healthy. If non-200, the binary should be terminated and restarted.
`/metrics` returns a [Prometheus](https://prometheus.io/) metrics endpoint for retrieving the results of the monitor.

