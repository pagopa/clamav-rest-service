# ClamAV REST service

Sandboxed file scanning with [ClamAV](https://www.clamav.net/) via REST API.

This application is a wrapper around a ClamAV daemon (`clamd`) consisting in:

* Python bindings for communications with `clamd` via Unix domain
  socket or TCP socket
* REST API for invoking `clamd` commands via socket. API bindings are
  written with the Flask framework
  
## Usage

When running the application, you can find API docs at `/swagger-ui`.

### Examples

Examples assume application running at `http://localhost:8080`.

Example: scan file
```
curl -X POST http://localhost:8080/api/v1/clamav/scan -F file=@Downloads/my-file-to-check.txt
```
response:
```json
{
  "details": [],
  "error": null,
  "file_size": <size>,
  "input_file": "-",
  "status": "OK",
  "virus": null
}
```

Example: test infected file
```
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | curl -X POST http://localhost:8080/api/v1/clamav/scan -F file=@-
```
response:
```json
{
  "details": [],
  "error": null,
  "file_size": 69,
  "input_file": "-",
  "status": "FOUND",
  "virus": "Eicar-Signature"
}
```

## Installation

As already stated, there are two ways in which the REST service can
interact with `clamd` daemon, resulting in two different deployment options.

### TL;DR

Just use the `ghcr.io/pagopa/clamav-rest-service:1.0.0-clamd` image
and you are good to go.

For example (local docker daemon):
```shell
docker run -d --name clamd-rest-service -p 8080:80 ghcr.io/pagopa/clamav-rest-service:1.0.0-clamd
```

### Bundled ClamAV

If `clamd` daemon is bundled in the same Unix-like host as the
`clamav-rest-service` can be deployed, inter-process communications
via Unix domain socket can be configured.

Configure the daemon to use local socket adding this line in `/etc/clamav/clamd.conf`:
```conf
LocalSocket /var/run/clamav/clamd.sock
```

Instruct the application to use local socket via environment variable:
```shell
CLAMAV_CLAMD_SOCKET_PATH=/path/to/clamd/domain/socket
```

This is considered the recommended option in the majority of cases, as
the burden in maintenance is considerably lower, especially if running
the pre-built image with bundled clamav.

In some advanced cases, you might prefer to use a ClamAV dedicated
installation, especially if you plan to replicate the REST service but
you want to use the same ClamAV instance and database (in fact, using
two different `clamd` instance targeting the same database in a shared
volume is not tested and may create concurrency problems).  In this
case, you can use the deployment option below.

### External ClamAV

If `clamd` daemon is installed on a different host, ensure it uses 
TCP socket in `/etc/clamav/clamd.conf`:
```conf
TCPSocket 8080
```
will expose TCP socket on port 8080.

Instruct the application to dial to the `clamd` TCP socket:
```shell
CLAMAV_CLAMD_HOST=my.clamd.host
CLAMAV_CLAMD_PORT=8080
```

> [!WARNING]
> The connection via TCP is obviously not encrypted: when using this
> option you should probably configure proper networking in order to
> protect the `clamd` instance and make it reachable only from the
> application

### Deploy with Docker

Images are provided for deployment in containerized runtimes, covering both cases (bundled and extenral).

You can find pre-built images in GitHub packages:
```shell
# clamav-rest-service WITHOUT clamav:
docker pull ghcr.io/pagopa/clamav-rest-service:1.0.0-clamd

# clamav-rest-service with BUNDLED clamav:
docker pull ghcr.io/pagopa/clamav-rest-service:1.0.0-slim
```

#### ClamAV-bundled image and virus database

ClamAV virus database is stored in the `/var/lib/clamav` directory in
the container (this option is customizable with the
`DatabaseDirectory` property in `clamd.conf`.  The database is rebuilt
when the container starts. You can opt this off simply by mounting a
volume in the database directory:
```shell
# example with named volume, you can obviusly use bind mount instead
docker volume create clamd_database
docker run -d \
    --name clamd-rest-service \
    -p 8080:80 \
    -v clamd_database:/var/lib/clamav \
    ghcr.io/pagopa/clamav-rest-service:1.0.0-clamd
```

The ClamAV bundled image runs also a pre-configured `freshclam` daemon
refreshing the database once a day (see
[freshclam.conf](docker/clamav/freshclam.conf).

> [!NOTE]
> During container startup you will see a warning like this: `WARNING:
> Tue Feb 4 15:39:54 2025 -> Clamd was NOT notified: Can't connect to
> clamd through /var/run/clamav/clamd.sock: No such file or directory`
> This is because we run `freshclam` before `clamd` to init the
> database, then we run freshclam daemon. This is intended and correct!

#### Build with docker

Examples with docker build:

```shell
# without clamav
docker build . -f docker/Dockerfile-slim -t clamav-rest-service:latest-slim

# with bundled clamav
docker build . -f docker/Dockerfile-clamd -t clamav-rest-service:latest-clamd
```

## Development

Poetry is needed.

Install:
```shell
poetry install
```

if you need gunicorn (you don't for local development in most cases):
```shell
poetry install --all-extras
```

Run test suite:

> [!NOTE]
> Tests do not have a clamd mock at the moment and they do require a running clamd daemon

```shell
poetry run pytest
```

Run application in dev mode:
```shell
poetry run python -m clamav_rest_service.__init__
```
