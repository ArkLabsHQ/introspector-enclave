# First image used to build the sources
FROM golang:1.25.5 AS builder

ARG VERSION
ARG NITRIDING_VERSION=c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f
ARG VIPROXY_VERSION=v0.1.2
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /app

# Copy go.mod and go.sum files first for better caching
COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/

# Download dependencies
RUN go mod download
RUN cd api-spec && go mod download

# Copy the rest of the source code
COPY . .

RUN mkdir -p /app/bin
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go install github.com/brave/nitriding-daemon@${NITRIDING_VERSION}
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go install github.com/brave/viproxy/example@${VIPROXY_VERSION} \
  && cp /go/bin/example /app/bin/viproxy

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags="-X 'main.Version=${VERSION}'" \
  -o /app/bin/introspector-skeleton .

# Second image, running the executable
FROM alpine:3.20

RUN apk update && apk upgrade
RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/bin/introspector-skeleton /app/
COPY --from=builder /go/bin/nitriding-daemon /app/nitriding
COPY --from=builder /app/bin/viproxy /app/proxy
COPY enclave/start.sh /app/start.sh

ARG VERSION
ARG AWS_REGION=us-east-1
ENV INTROSPECTOR_DEPLOYMENT=${VERSION}
ENV INTROSPECTOR_AWS_REGION=${AWS_REGION}

ENV PATH="/app:${PATH}"
ENV INTROSPECTOR_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT ["/app/start.sh"]
