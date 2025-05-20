FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

RUN apk add --no-cache tzdata tini

# Copy ic-gateway binary
COPY target/x86_64-unknown-linux-musl/release/ic-gateway /usr/sbin

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/sbin/ic-gateway"]
