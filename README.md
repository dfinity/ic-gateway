# ic-gateway

`ic-gateway` is the core service of the HTTP gateway that allows direct HTTP access to the canisters hosted on the [Internet Computer](https://internetcomputer.org).

## Description

`ic-gateway` enables direct HTTP access to canisters hosted on the Internet Computer, allowing you to host full dapps - both frontend and backend - entirely on-chain. It translates incoming HTTP requests into IC API calls and maps the canisters' responses back into HTTP responses.

`ic-gateway` also provides essential features for running a production HTTP gateway, including:

- **TLS Termination**: Automatically obtains and renews certificates using an ACME client and transparent OCSP stapling.
- **Caching Layer**: Improves user-perceived performance of hosted dapps.
- **Denylist**: Allows compliance with local legal frameworks (e.g., by restricting access to illegal content).
- **Load Shedding**: Drops the incoming requests if the moving average latency grows over defined threshold.

## Installation

To install and set up `ic-gateway`, follow these steps:

### Simple

- Grab the latest package from the [releases](https://github.com/dfinity/ic-gateway/releases) page and install it
- Edit `/etc/default/ic-gateway` file to configure the service using environment variables. See `Usage` section below.
- Start the service with `systemctl start ic-gateway`

### Advanced

- **Clone the repository**

  ```bash
  git clone git@github.com:dfinity/ic-gateway.git
  cd ic-gateway
  ```

- **Install Rust**

  Follow the [official Rust installation guide](https://www.rust-lang.org/tools/install).

- **Build**
  
  Execute `cargo build --release` in the `ic-gateway` folder and you'll get a binary in `target/release` subfolder.

- **Generate the certificate**

  If you want to run the service locally you'll need a certificate.

  Store the certificate and private key in a directory with the names `<domain>.pem` and `<domain>.key`, respectively. For example, to serve the domain `gateway.icp`, the files should be named `gateway.icp.pem` and `gateway.icp.key`.

  For local testing, you can use self-signed certificates created with [mkcert](https://github.com/FiloSottile/mkcert). For production, obtain a certificate from [Let's Encrypt](https://letsencrypt.org/) using [`certbot`](https://certbot.eff.org/) or the built-in certificate provider.

### Reproducible build

 - Install [repro-env](https://github.com/kpcyrd/repro-env)
 - Build the binary using `repro-env build -- cargo build --release --target x86_64-unknown-linux-musl`

### Running in Docker
 - Pull the container: `docker pull ghcr.io/dfinity/ic-gateway:latest`
 - Create the configuration file with the environment variables, e.g. `ic-gateway.env`
 - Run the container: `docker run --env-file ic-gateway.env ghcr.io/dfinity/ic-gateway`

## Usage

### Requirements

- Domain name that points to the IP address where `ic-gateway` will be running. It's denoted as `gateway.icp` in the examples below.
- Port 443 open in the firewall

### Minimal Example

To run a minimal ic-gateway instance, use the following configuration in `/etc/default/ic-gateway`:

```
LOG_STDOUT="true"
HTTP_SERVER_LISTEN_TLS="[::]:443"
IC_URL="https://icp-api.io"
DOMAIN="gateway.icp"
ACME_CHALLENGE="alpn"
ACME_CACHE_PATH="/var/lib/ic-gateway/acme"
```

Create a folder to store ACME certificates & account info:
```
# mkdir -p /var/lib/ic-gateway/acme
```

Start the service:
```
# systemctl start ic-gateway
```

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

`ic-gateway` offers various options that can be configured via command-line arguments or environment variables. For a full list, run `ic-gateway --help`.

Key settings include:

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
