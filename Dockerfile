# Chonkline — Rust IRC server. Multi-stage: build with cargo, ship on distroless.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin irc-server

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/irc-server /usr/local/bin/chonkline
# LLM-generated release notes served by the web property (read at runtime).
COPY --from=build /src/src/web/release-notes.json /usr/local/share/chonkline/release-notes.json
# Plain-TCP IRC on 6667; read-only web property on 8080.
ENV IRC_PORT=6667
ENV IRC_HTTP_PORT=8080
ENV IRC_RELEASE_NOTES_PATH=/usr/local/share/chonkline/release-notes.json
EXPOSE 6667 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/chonkline"]
