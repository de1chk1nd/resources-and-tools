"""
Top-level entry point: python -m xc_ns_mover <subcommand>

Subcommands:
    scanner  — list all LBs across namespaces, export CSV + HTML report
    mover    — move LBs from a CSV into a target namespace
"""

import sys


USAGE = """\
usage: python -m xc_ns_mover <command>

commands:
  scanner   List all HTTP/HTTPS load balancers across namespaces -> CSV + HTML report
  mover     Move HTTP load balancers (and dependencies) to a target namespace

Run 'python -m xc_ns_mover.<command> --help' for command-specific options.
"""


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0)

    command = sys.argv[1]
    # Remove the subcommand from argv so the subcommand's argparse sees clean args
    sys.argv = [f"xc_ns_mover.{command}"] + sys.argv[2:]

    if command == "scanner":
        from .scanner.cli import main as scanner_main
        scanner_main()
    elif command == "mover":
        from .mover.cli import main as mover_main
        mover_main()
    else:
        print(f"Unknown command: {command}\n")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()
