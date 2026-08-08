FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /secret-server ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /secret-server /secret-server
ENTRYPOINT ["/secret-server"]
