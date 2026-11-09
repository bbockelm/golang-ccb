# Multi-stage build for the standalone Go HTCondor Connection Broker (CCB).
#
# htc-ccb is a self-contained, pure-Go server: it re-implements the CCB wire
# protocol and reads HTCondor configuration/credentials directly, so it does not
# need the HTCondor binaries installed to run. modernc.org/sqlite is cgo-free, so
# we build a fully static binary and ship it on a minimal distroless base.
#
# Build:
#   docker build -t htc-ccb .
# Run (advertise a reachable address; mount config + pool signing key):
#   docker run --rm -p 9618:9618 \
#     -e CONDOR_CONFIG=/etc/condor/condor_config \
#     -v /etc/condor:/etc/condor:ro \
#     htc-ccb -listen :9618 -public <public-host>:9618

# ---- build stage ----
FROM golang:1.27 AS build

WORKDIR /src

# Download modules first so the layer caches unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped, reproducible binary. buildvcs=false because .git is not in
# the build context (see .dockerignore).
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/htc-ccb ./cmd/htc-ccb

# The runtime stage has no dynamic loader and no libc, so a cgo binary would
# build here and then fail to exec with an error naming neither. Read the
# binary rather than trust the variable above.
RUN ./packaging/check-static.sh /out/htc-ccb

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/htc-ccb /usr/local/bin/htc-ccb

# Default CCB control port. Override the advertised address with -public and the
# configuration/credentials location with CONDOR_CONFIG at run time.
EXPOSE 9618

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/htc-ccb"]
CMD ["-listen", ":9618"]
