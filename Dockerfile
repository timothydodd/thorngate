# ---- build ----
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# Set by the release workflow from the git tag; shown in the admin portal.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /thorngate ./cmd/thorngate

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /thorngate /thorngate
USER nonroot:nonroot
EXPOSE 8765
ENTRYPOINT ["/thorngate", "-config", "/etc/thorngate/config.json"]
