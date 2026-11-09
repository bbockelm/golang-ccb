# Both non-proxy roles of the squid end-to-end test: the offsite broker and the
# worker node's harness. One image, two entrypoints, so the binaries under test
# are built once from the working tree.
FROM golang:1.27 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/golang-ccb ./cmd/golang-ccb \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/e2esetup ./test/e2e-squid/cmd/e2esetup \
 && CGO_ENABLED=0 go test -tags squide2e -c -o /out/squid-e2e.test ./test/e2e-squid/

FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/golang-ccb /usr/local/bin/golang-ccb
COPY --from=build /out/e2esetup /usr/local/bin/e2esetup
COPY --from=build /out/squid-e2e.test /usr/local/bin/squid-e2e.test
COPY test/e2e-squid/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
