# Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/main.go

# Run
FROM alpine:latest

RUN apk add --no-cache ca-certificates bash

WORKDIR /root/

COPY --from=builder /app/main .
COPY wait-for-it.sh .

EXPOSE 8080

CMD ["./wait-for-it.sh", "db", "5432", "--", "./main"]
