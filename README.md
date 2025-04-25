Certhoover
==========

Certhoover is an async Rust service that subscribes to the certificate transparency firehose from [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go), batches incoming records, and inserts them into ClickHouse for fast analytics.

## Features
- **Async, high-performance**: Built with `tokio` and `tokio-tungstenite` for efficient websocket handling and batching.
- **Robust error handling**: Uses the `anyhow` crate for rich error context and propagation.
- **Configurable**: All connection details are set in a `config.toml` file; override with the `CERTHOOVER_CONFIG` environment variable.
- **Tested and linted**: Includes a suite of integration tests and enforces code quality with Clippy.

## Quick Start

1. **Clone and build:**
   ```sh
   git clone https://github.com/YOUR_USER/certhoover.git
   cd certhoover
   cargo build --release
   ```
2. **Configure:**
   Create a `config.toml` in the project root (see below), or set `CERTHOOVER_CONFIG` to your config path.
3. **Run:**
   ```sh
   cargo run --release
   ```

## Example config.toml

```toml
[certstream]
url = "ws://127.0.0.1:8080/" # Replace with your certstream-server-go endpoint

[clickhouse]
host = "localhost"
port = 9000
user = "default"
password = ""
database = "default"

[service]
liveness_path = "/run/certhoover/liveness"
batch_size = 1000
max_batch_age_secs = 5
logging_level = "info"
```

- The `[service]` section allows you to control batching, logging, and liveness file output.
- For best results, use a modern Certstream server such as [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go).

## Development

- **Run tests:**
  ```sh
  cargo test
  ```
- **Run linter (Clippy, deny warnings):**
  ```sh
  cargo clippy --all-targets --all-features -- -D warnings
  ```

## Architecture Overview
- **Websocket Client:** Connects to Certstream and reads certificate events asynchronously.
- **Batcher:** Groups incoming records into batches based on size and age.
- **Inserter:** Writes batches to ClickHouse, creating the table if needed.
- **Error Handling:** All operations use `anyhow::Result` for robust error context and graceful failure.

## Main Dependencies
- [`tokio`](https://crates.io/crates/tokio) (async runtime)
- [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) (async websockets)
- [`clickhouse-rs`](https://crates.io/crates/clickhouse-rs) (ClickHouse driver)
- [`serde`, `serde_json`](https://serde.rs/) (serialization)
- [`anyhow`](https://crates.io/crates/anyhow) (error handling)
- [`log`, `env_logger`](https://crates.io/crates/log) (logging)

## Contributing
Pull requests and issues are welcome! Please:
- Run `cargo test` and `cargo clippy --all-targets --all-features -- -D warnings` before submitting.
- Document new features and public APIs with Rustdoc comments.

---

If the config file is missing or malformed, the service will print an error and exit.
