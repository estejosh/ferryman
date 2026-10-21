FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p orchestrator-server
FROM debian:bookworm-slim
RUN useradd --system --create-home bridge
COPY --from=build /src/target/release/orchestrator-server /usr/local/bin/
USER bridge
EXPOSE 8787
ENTRYPOINT ["orchestrator-server"]
