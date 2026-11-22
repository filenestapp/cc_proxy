# Linux test image for the client: the ccproxy CLI (static musl build) on top of python + sing-box.
# Build context: the client/ directory.
FROM rust:1.95-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core core
COPY cli cli
# The desktop (Tauri) crate is not needed here and is not copied; drop it from the workspace.
RUN sed -i 's#, *"desktop/src-tauri"##' Cargo.toml && cargo build --release -p ccproxy

FROM egress-e2e-tunclient
COPY --from=build /src/target/release/ccproxy /usr/local/bin/ccproxy
ENTRYPOINT []
