# The hardenkit CLI as a container image.
#
#   docker run --rm -v "$PWD:/src" ghcr.io/hardenkit/scan scan /src
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /hardenkit ./cmd/hardenkit

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /hardenkit /usr/local/bin/hardenkit
ENTRYPOINT ["/usr/local/bin/hardenkit"]
