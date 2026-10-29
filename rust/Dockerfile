# netportal (Rust): one image for the portal and its two sidecars (docs/ARCHITECTURE.md):
#   netportal serve                      the portal on 0.0.0.0:8080 (the default command)
#   netportal offboard --every 900       the offboarding sidecar
#   netportal collect                    the collector
#   netportal init-db                    schema, the radius role's rights, seeds (a one-shot)
# Healthchecks without a shell tool: `netportal health web` (GET /healthz, the image's own
# HEALTHCHECK) and `netportal health heartbeat --file F --max-age S` for the sidecars.
#
# Built from the repository ROOT, as house-infra builds it from a git context
# ("<repo>.git#<commit>" with dockerfile: rust/Dockerfile):
#   docker build -f rust/Dockerfile -t netportal-rust .
# The context is the whole repository because the binary embeds netportal/static/ (served
# unchanged); rust/Dockerfile.dockerignore (BuildKit reads it instead of the root .dockerignore,
# which leaves rust/ out of the Python image) sends only rust/ without target/, and
# netportal/static/.
#
# Runs as uid 10001 (as the Python image), with a read-only root filesystem: the only writes are
# the sidecars' heartbeat files in /tmp (a tmpfs in house-infra). No compiler, no package
# manager use at run time, no curl: libssl3 (the openssl crate: X.509, PKCS#12) and
# ca-certificates (Authentik over https; it brings the openssl CLI, which nothing calls) added to
# Debian's slim base. Time zones are bundled in the binary (jiff).

# Build: the same Debian release as the run stage (glibc and libssl ABI).
FROM rust:1.97.1-trixie@sha256:b1b3c9c0d921d7fa0a6d1f9ec7e4eab87f8c8ec97644c3d791450f131dec813f AS build
WORKDIR /src
COPY netportal/static/ netportal/static/
COPY rust/ rust/
WORKDIR /src/rust
# --locked: exactly Cargo.lock (the versions cargo-deny and cargo-audit checked). The cache
# mounts only speed up rebuilds; the binary is copied out of the target cache in the same step.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rust/target \
    cargo build --release --locked -p netportal \
 && install -D -m 0755 target/release/netportal /out/netportal

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 ca-certificates \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /var/log/apt /var/log/dpkg.log \
 && groupadd --system --gid 10001 netportal \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin netportal
COPY --from=build /out/netportal /usr/local/bin/netportal
USER netportal
WORKDIR /
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/netportal", "health", "web"]
ENTRYPOINT ["/usr/local/bin/netportal"]
CMD ["serve"]
