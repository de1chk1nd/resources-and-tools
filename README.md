# Resources and Tools

A collection of utilities and helper scripts for day-to-day infrastructure and security work — mostly around F5 Distributed Cloud (XC), certificate management, and general troubleshooting.

## Tools

| Tool | Description |
|------|-------------|
| [jwt-decode](tools/jwt-decode/) | Interactive CLI tool to decode and inspect JWT tokens |
| [s-certificate](tools/s-certificate/) | Generate server certificates signed by your own CA |
| [xc-troubleshooting](tools/xc-troubleshooting/) | Query F5 XC security event logs and generate troubleshooting reports |

### jwt-decode

Simple Python script that decodes a JWT token (without signature verification) and pretty-prints the header, payload, and signature. Useful for quickly inspecting tokens during debugging.

```bash
cd tools/jwt-decode
pip install PyJWT
python jwt-decode.py
```

See [tools/jwt-decode/README.md](tools/jwt-decode/README.md) for details.

### s-certificate

Generates server certificates signed by your own Certificate Authority. Provide a domain name and it produces a `.p12` bundle — handy for lab environments and demo setups.

```bash
cd tools/s-certificate
python generate_s-cert.py mydomain.org
```

See [tools/s-certificate/README.md](tools/s-certificate/README.md) for details.

### xc-troubleshooting

CLI tool that queries F5 Distributed Cloud security event logs by request ID, source IP, FQDN, or any combination, and generates local troubleshooting reports in Markdown, HTML, or JSON.

```bash
cd tools/xc-troubleshooting
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
python src/xc_troubleshoot.py --req-id "abc123"
```

See [tools/xc-troubleshooting/README.md](tools/xc-troubleshooting/README.md) for full documentation.

## Repository Structure

```
resources-and-tools/
├── tools/
│   ├── jwt-decode/          # JWT token decoder
│   ├── s-certificate/       # Self-signed certificate generator
│   └── xc-troubleshooting/  # F5 XC WAAP troubleshooting tool
├── .gitignore
├── LICENSE
└── README.md
```

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
