FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /identity ./cmd/identity
FROM alpine:3.22
COPY --from=build /identity /identity
USER 65532
EXPOSE 8091
ENTRYPOINT ["/identity"]
