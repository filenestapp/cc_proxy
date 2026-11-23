FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go schema.sql console.html sqlite_export.py ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/cc-controlplane .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/cc-controlplane /usr/local/bin/cc-controlplane
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["cc-controlplane"]
CMD ["serve", "--listen", "0.0.0.0"]
