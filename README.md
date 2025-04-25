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
# Enable systemd watchdog notifications (requires libsystemd-dev and WatchdogSec in service file)
enable_systemd_notify = true
batch_size = 1000
max_batch_age_secs = 5
logging_level = "info"
```

- The `[service]` section allows you to control batching, logging, and systemd integration.
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

## Systemd Service Installation

To run Certhoover as a background service on Linux, you can install it as a `systemd` service. This is the recommended way to run Certhoover in production.

### 1. Build and Install the Binary
```sh
cargo build --release
sudo cp target/release/certhoover /usr/local/bin/
```

### 2. Create a Dedicated System User
It is best practice to run Certhoover as a non-privileged system user:
```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin certhoover
```

### 3. Place Your Config
Make sure your `config.toml` is readable by the `certhoover` user. For example:
```sh
sudo mkdir -p /etc/certhoover
sudo cp config.toml /etc/certhoover/config.toml
sudo chown -R certhoover:certhoover /etc/certhoover
```

### 4. Install the systemd Unit File

**Note:** If you want to use systemd integration (watchdog notifications), you must have the `libsystemd-dev` package installed on your system before building Certhoover from source. On Debian/Ubuntu, install it with:
```sh
sudo apt install libsystemd-dev
```

A sample and up-to-date `certhoover.service` file is provided in this repository. To install it:

```sh
sudo cp certhoover.service /etc/systemd/system/certhoover.service
```

**Review and edit** the file as needed:
- Adjust `ExecStart` to match your binary location (e.g., `/usr/local/bin/certhoover` or `/var/lib/certhoover/certhoover`).
- Set `WorkingDirectory` and `CERTHOOVER_CONFIG` to your desired config and runtime paths.
- Ensure the `User` and `Group` match your created system user.

See comments in the `certhoover.service` file for further customization and liveness/Watchdog settings.

### 5. Enable and Start the Service
```sh
sudo systemctl daemon-reload
sudo systemctl enable certhoover
sudo systemctl start certhoover
sudo systemctl status certhoover
```

---

If the config file is missing or malformed, the service will print an error and exit.
