# Both non-proxy roles of the squid end-to-end test: the offsite broker and the
# worker node's harness. One image, two entrypoints, so the binaries under test
# are built once from the working tree.
FROM golang:1.27 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/htc-ccb ./cmd/htc-ccb \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/e2esetup ./test/e2e-squid/cmd/e2esetup \
 && CGO_ENABLED=0 go test -tags squide2e -c -o /out/squid-e2e.test ./test/e2e-squid/

FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# htc-ccb refuses to run as root ("privilege drop left the process running as
# root"), which is the right default and the opposite of a container's. So the
# image carries a non-root account, and compose runs both roles as it. The
# carrier still has to listen on 443 -- a stock squid will CONNECT nowhere else
# -- which a non-root process manages via net.ipv4.ip_unprivileged_port_start,
# set per container in docker-compose.yml.
RUN groupadd --gid 10000 ccb \
 && useradd --uid 10000 --gid 10000 --create-home --shell /usr/sbin/nologin ccb \
# A fresh named volume inherits the ownership of the image content at its mount
# point, so creating /shared here is what makes it writable by ccb.
 && mkdir -p /shared \
 && chown ccb:ccb /shared

COPY --from=build /out/htc-ccb /usr/local/bin/htc-ccb
COPY --from=build /out/e2esetup /usr/local/bin/e2esetup
COPY --from=build /out/squid-e2e.test /usr/local/bin/squid-e2e.test
COPY test/e2e-squid/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
