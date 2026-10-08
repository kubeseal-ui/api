# Use the official Golang image to build the application
FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download 2>/dev/null || true

COPY . .

ARG VERSION=""
RUN if [ -n "$VERSION" ]; then echo "$VERSION" > /app/version.txt; elif [ ! -f /app/version.txt ]; then echo "dev-unknown" > /app/version.txt; fi

RUN CGO_ENABLED=0 go build -o /kubeseal-api ./cmd/server

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /kubeseal-api .
COPY --from=builder /app/version.txt ./version.txt

EXPOSE 8080

CMD ["./kubeseal-api"]