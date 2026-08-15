# Chonkline — Rust IRC server. Multi-stage: build with cargo, ship on distroless.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin irc-server

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/irc-server /usr/local/bin/chonkline
# Plain-TCP IRC. Non-TLS launch: listen on the classic 6667.
ENV IRC_PORT=6667
EXPOSE 6667
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/chonkline"]
