FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kardia ./cmd/kardia

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/kardia /usr/local/bin/kardia
COPY bpf /opt/kardia/bpf
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kardia"]
CMD ["-mode=analyzer", "-listen=:8080", "-scenario=off"]
