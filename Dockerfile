FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=github_token \
    git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" && \
    go mod download && \
    git config --global --unset-all url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /secret-server ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /secret-server /secret-server
ENTRYPOINT ["/secret-server"]
