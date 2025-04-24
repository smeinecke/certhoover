Certhoover
==========

Subscribes to certificate transparency record firehose from [Certstream](https://certstream.calidog.io/), buffers data
into batches, and then inserts into ClickHouse.

## Configuration

certhoover is configured via a `config.toml` file in the project root by default. You can override the config file location by setting the `CERTHOOVER_CONFIG` environment variable.

Example:

```sh
CERTHOOVER_CONFIG=/path/to/your/config.toml cargo run
```

### Example config.toml

```toml
[certstream]
url = "wss://certstream.calidog.io/"

[clickhouse]
host = "localhost"
port = 9000
user = "default"
password = ""
database = "default"
```

- All connection details for Certstream and ClickHouse are set here.
- If the config file is missing or malformed, the service will print an error and exit.
