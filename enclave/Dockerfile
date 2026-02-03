# First image used to build the sources
FROM golang:1.25.5 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy go.mod and go.sum files first for better caching
COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/
COPY pkg/arkade/go.mod pkg/arkade/go.sum ./pkg/arkade/
COPY pkg/client/go.mod pkg/client/go.sum ./pkg/client/

# Download dependencies
RUN go mod download
RUN cd api-spec && go mod download
RUN cd pkg/arkade && go mod download
RUN cd pkg/client && go mod download

# Copy the rest of the source code
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags="-X 'main.Version=${VERSION}'" \
  -o /app/bin/introspector-skeleton ./cmd/enclave-skeleton

# Second image, running the executable
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/introspector-skeleton /app/
COPY enclave/start.sh /app/start.sh

ENV PATH="/app:${PATH}"
ENV INTROSPECTOR_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT ["/app/start.sh"]
