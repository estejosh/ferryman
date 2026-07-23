FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p ferryman-server
FROM debian:bookworm-slim
RUN useradd --system --create-home bridge
COPY --from=build /src/target/release/ferryman-server /usr/local/bin/
USER bridge
EXPOSE 8787
ENTRYPOINT ["ferryman-server"]
