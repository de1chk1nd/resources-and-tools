# Resources and Tools

A collection of utilities and helper scripts for day-to-day infrastructure and security work — mostly around F5 Distributed Cloud (XC), certificate management, and general troubleshooting.

## Tools

| Tool | Description |
|------|-------------|
| [jwt-decode](tools/jwt-decode/) | Decode and inspect JWT tokens (interactive, argument, or stdin) |
| [s-certificate](tools/s-certificate/) | Generate server certificates signed by your own CA |
| [xc-ns-mover](tools/xc-ns-mover/) | Move HTTP load balancers between F5 XC namespaces |
| [xc-troubleshooting](tools/xc-troubleshooting/) | Query F5 XC security event logs and generate troubleshooting reports |

### jwt-decode

Decode and inspect JWT (JSON Web Token) tokens without signature verification. Pretty-prints header, payload, and signature. Supports interactive prompt, CLI argument, and stdin piping. No external dependencies.

```bash
cd tools/jwt-decode
./bin/run-jwt-decode.sh                           # interactive prompt
./bin/run-jwt-decode.sh "<token>"                  # pass token as argument
echo "<token>" | ./bin/run-jwt-decode.sh --stdin   # pipe via stdin
```

See [tools/jwt-decode/README.md](tools/jwt-decode/README.md) for details.

### s-certificate

Generates server certificates signed by your own Certificate Authority, with optional upload to F5 Distributed Cloud (XC). Provide a domain name and it produces a `.p12` bundle — handy for lab environments and demo setups.

```bash
cd tools/s-certificate
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
./bin/run-s-certificate.sh mydomain.org
```

See [tools/s-certificate/README.md](tools/s-certificate/README.md) for full documentation.

### xc-ns-mover

Moves HTTP load balancers (and their dependencies) between F5 Distributed Cloud namespaces. Includes a **scanner** to discover all LBs across namespaces and a **mover** that handles dependency resolution, conflict detection, certificate pre-flight checks, rollback on failure, and detailed HTML reporting.

```bash
cd tools/xc-ns-mover
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
./bin/run-scanner.sh            # list all LBs -> CSV + HTML report
./bin/run-mover.sh --dry-run    # pre-migration report (no changes)
./bin/run-mover.sh              # execute migration
```

See [tools/xc-ns-mover/README.md](tools/xc-ns-mover/README.md) for full documentation.

### xc-troubleshooting

CLI tool that queries F5 Distributed Cloud security event logs by request ID, source IP, FQDN, or any combination, and generates local troubleshooting reports in Markdown, HTML, or JSON.

```bash
cd tools/xc-troubleshooting
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
./bin/run-troubleshoot.sh --req-id "abc123"
```

See [tools/xc-troubleshooting/README.md](tools/xc-troubleshooting/README.md) for full documentation.

## Repository Structure

```
resources-and-tools/
├── tools/
│   ├── jwt-decode/          # JWT token decoder
│   │   ├── bin/             #   Shell wrapper
│   │   ├── docs/            #   Reference guide
│   │   └── src/jwt_decode/  #   Python package
│   ├── s-certificate/       # Self-signed certificate generator
│   │   ├── bin/             #   Shell wrapper
│   │   ├── config/          #   YAML config + examples
│   │   ├── docs/            #   Reference guide
│   │   └── src/s_certificate/
│   ├── xc-ns-mover/         # F5 XC namespace LB mover
│   │   ├── bin/             #   Shell wrappers (scanner + mover)
│   │   ├── config/          #   YAML config + CSV input
│   │   ├── docs/            #   Reference guide
│   │   └── src/xc_ns_mover/
│   └── xc-troubleshooting/  # F5 XC WAAP troubleshooting tool
│       ├── bin/             #   Shell wrapper
│       ├── config/          #   YAML config
│       ├── docs/            #   Reference guide
│       └── src/xc_troubleshoot/
├── .gitignore
├── LICENSE
└── README.md
```

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
