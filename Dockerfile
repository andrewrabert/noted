# Build stage: latest stable 1.x, Debian bookworm based so its glibc matches the
# bookworm-slim runtime below. It also ships the C toolchain that rusqlite's
# `bundled` feature (compiles SQLite from C) and `ring` need. (Cargo.toml's
# rust-version 1.90 is only an MSRV floor, not a build pin.)
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin noted

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/noted /usr/local/bin/noted

# NOTED_DIR is the notes/Tasks tree; mount a volume here to persist it.
ENV NOTED_DIR=/data
# Bind to all interfaces so the published port is reachable (default is 127.0.0.1).
ENV NOTED_HOST=0.0.0.0
ENV NOTED_PORT=8000
VOLUME ["/data"]
EXPOSE 8000

# REST tool API at /tool/{Name} and the MCP Streamable-HTTP app at /mcp.
# Set NOTED_AUTH_DB to require bearer auth.
ENTRYPOINT ["noted"]
CMD ["server", "http"]
