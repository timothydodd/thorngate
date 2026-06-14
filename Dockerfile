# ---- build ----
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /thorngate ./cmd/thorngate

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /thorngate /thorngate
USER nonroot:nonroot
EXPOSE 8765
ENTRYPOINT ["/thorngate", "-config", "/etc/thorngate/config.json"]
