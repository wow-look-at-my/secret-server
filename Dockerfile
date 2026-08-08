FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /secret-server ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /secret-server /secret-server

# Metadata only -- this publishes nothing on the host. It is what lets
# docker-updater find the port serving /.well-known/docker-updater/ without a
# per-deployment label.
EXPOSE 8080

ENTRYPOINT ["/secret-server"]
