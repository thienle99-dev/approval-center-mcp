FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/approval-center ./cmd/approval-center

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S -g 10001 approval && adduser -S -D -H -u 10001 -G approval approval && mkdir -p /data && chown 10001:10001 /data
COPY --from=build /out/approval-center /usr/local/bin/approval-center
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/approval-center"]
