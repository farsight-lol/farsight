# farsight — the worldwide port scanner
farsight is a masscan alternative with extended banner support (figuring out what the scanned servers are), and the ability to save data to analytical databases like clickhouse. utilizing AF_XDP technology, farsight is able to saturate NIC queues *very fast* without monopolizing a NIC.

it is written fully in Rust with its own AF_XDP wrapper, and sometimes utilizes unsafe code to increase performance.

# FAQ
## why won't my program start?
try copying the `config.example.toml` file into a file named `config.toml` and changing the configuration values in that file to your liking. there are comments present in said file that may help you with any issues.
