# ic-gateway

`ic-gateway` is the core service of the HTTP gateway that allows direct HTTP access to the canisters hosted on [the Internet Computer](https://internetcomputer.org).

## Description

`ic-gateway` enables direct HTTP access to canisters hosted on the Internet Computer, allowing you to host full dapps -- both frontend and backend -- entirely on-chain. It translates incoming HTTP requests into IC API calls and maps the canisters' responses back into HTTP responses.

`ic-gateway` also provides essential features for running a production HTTP gateway, including:

- **TLS Termination:** Automatically obtains and renews certificates using an ACME client.
- **Caching Layer:** Improves user-perceived performance of hosted dapps.
- **Denylist:** Allows compliance with local legal frameworks (e.g., by restricting access to illegal content).

## Installation

To install and set up `ic-gateway`, follow these steps:

- **Clone the repository**

  ```bash
  git clone git@github.com:dfinity/ic-gateway.git
  cd ic-gateway
  ```

- **Install Rust**

  Follow the [official Rust installation guide](https://www.rust-lang.org/tools/install).

- **Provide a certificate**

  Store the certificate and private key in a directory with the names `<domain>.pem` and `<domain>.key`, respectively. For example, to serve the domain `gateway.icp`, the files should be named `gateway.icp.pem` and `gateway.icp.key`.

  For local testing, you can use self-signed certificates created with [mkcert](https://github.com/FiloSottile/mkcert). For production, obtain a certificate from [Let's Encrypt](https://letsencrypt.org/) using [`certbot`](https://certbot.eff.org/) or the built-in certificate provider.

## Usage

### Requirements

- Rust
- A domain name and a corresponding certificate

### Minimal Example

To run a minimal ic-gateway locally, use the following command:

```
cargo run -- \
    --log-stdout \
    --http-server-listen-tls '127.0.0.1:443' \
    --ic-url https://icp-api.io \
    --domain gateway.icp \
    --cert-provider-dir ./certs
```

This starts `ic-gateway` on port 443 on localhost (`--http-server-listen-tls`), uses `https://icp-api.io` as the upstream (`--ic-url`), serves the domain `gateway.icp` (`--domain`), and expects the certificate `gateway.icp.pem` and private key `gateway.icp.key` in the `certs` directory (`--cert-provider-dir`).

Once it is running, you can test it from the command-line using the following `curl` commands:

```
# fetch the NNS dapp
curl -sLv \
    --resolve qoctq-giaaa-aaaaa-aaaea-cai.gateway.icp:443:127.0.0.1 \
    https://qoctq-giaaa-aaaaa-aaaea-cai.gateway.icp

# fetch the main Internet Computer site
curl -sLv \
    --resolve oa7fk-maaaa-aaaam-abgka-cai.gateway.icp:443:127.0.0.1 \
    https://oa7fk-maaaa-aaaam-abgka-cai.gateway.icp

# fetch the Internet Identity dapp
curl -sLv \
    --resolve rdmx6-jaaaa-aaaaa-aaadq-cai.gateway.icp:443:127.0.0.1 \
    https://rdmx6-jaaaa-aaaaa-aaadq-cai.gateway.icp
```

### Options

`ic-gateway` offers various options that can be configured via command-line arguments or environment variables. For a full list, see [`cli.rs`](src/cli.rs). Key settings include:

#### HTTP Server

- **`--http-server-listen-plain`**: Address for HTTP connections (only redirect to HTTPS).
- **`--http-server-listen-tls`**: Address for HTTPS connections.

#### Domain

- **`--domain`**: Domains served by `ic-gateway`
- **`--domain-canister-alias`**: "Pretty" names for specific canisters (e.g., `nns` instead of `qoctq-giaaa-aaaaa-aaaea-cai`).

#### Policy

- **`--policy-denylist-*`**: All options to configure a canister denylist.

#### IC

- **`--ic-url`**: URL of the upstream API boundary nodes.
- **`--ic-use-discovery`**: Use discovery library for API boundary nodes.

#### ACME

Configures certificate management via from Let's Encrypt using either the [`TLS-ALPN-01`](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01) or the [`DNS-01`](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) challenge. This is mostly suitable for single instance deployments.

#### Metrics & Logging

- **`--metrics-listen`**: Port for Prometheus metrics scraping.
- Logging options like log level and output destination

## Contributing

External code contributions are currently not being accepted to this repository.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for more details.
