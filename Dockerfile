FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=""
RUN if [ -n "$VERSION" ]; then echo "$VERSION" > /app/version.txt; elif [ ! -f /app/version.txt ]; then echo "dev-unknown" > /app/version.txt; fi

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /kubeseal-api ./cmd/server

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /kubeseal-api .
COPY --from=builder /app/version.txt ./version.txt

EXPOSE 8080

CMD ["./kubeseal-api"]