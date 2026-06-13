# KubeDagger

<p align="center">
  <img src="https://github.com/yasindce1998/KubeDagger/blob/master/logo/logo-removebg-preview.png?raw=true" alt="KubeDagger"/>
</p>

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

An eBPF-based security research tool that demonstrates offensive techniques including network discovery, file system monitoring, process hiding, and container breakouts.

## Disclaimer

This project is provided for **educational purposes only**. Do not use these tools to violate the law. The author is not responsible for any illegal action. Misuse of the provided information can result in criminal charges.

## Requirements

- Linux kernel 5.4+ with eBPF support
- Go 1.22+
- Kernel headers installed in `lib/modules/$(uname -r)`
- clang & llvm 11+
- [Graphviz](https://graphviz.org/) (for network graph generation)

## Build

```shell
make
```

To install the client to `/usr/bin/`:

```shell
make install_client
```

## Usage

Start the rootkit (requires root):

```shell
sudo ./bin/kubedagger -h
```

Start the C2 webapp:

```shell
./bin/webapp -h
```

Use the client to interact:

```shell
kubedagger-client -h
```

### Available client commands

| Command | Description |
|---------|-------------|
| `docker` | Docker image override configuration |
| `fs_watch` | File system watches |
| `network_discovery` | Network discovery and port scanning |
| `pipe_prog` | Piped programs configuration |
| `postgres` | PostgreSQL authentication control |

## License

- Go code: Apache 2.0
- eBPF programs: GPL v2
