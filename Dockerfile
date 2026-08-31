# Use the official Golang image to build the application
FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download 2>/dev/null || true

COPY . .

RUN CGO_ENABLED=0 go build -o /kubeseal-api ./cmd/server

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /kubeseal-api .

EXPOSE 8080

CMD ["./kubeseal-api"]