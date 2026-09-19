import sys
import json
import argparse
from pathlib import Path
from app.ingestion.parser import PcapIngester

def main():
    parser = argparse.ArgumentParser(
        description="Offline Network Forensic PCAP Ingester for Email Infrastructure (SMTP, IMAP, POP3)"
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        help="Path to .pcap or .pcapng network capture file"
    )
    parser.add_argument(
        "--pcap", "-p",
        dest="pcap_flag",
        help="Path to .pcap or .pcapng network capture file"
    )
    parser.add_argument(
        "--output", "-o",
        help="Optional destination path to write output JSON"
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON output indentation level (default: 2)"
    )

    args = parser.parse_args()
    pcap_path = args.pcap_file or args.pcap_flag

    if not pcap_path:
        parser.print_help()
        sys.exit(1)

    path = Path(pcap_path)
    if not path.exists():
        print(f"Error: Specified PCAP file '{pcap_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    try:
        ingester = PcapIngester(str(path))
        sessions = ingester.parse()
        
        # Serialize Pydantic sessions to JSON
        sessions_data = [session.model_dump() for session in sessions]
        json_output = json.dumps(sessions_data, indent=args.indent)

        if args.output:
            with open(args.output, "w") as f:
                f.write(json_output)
            print(f"[+] Successfully wrote {len(sessions)} reconstructed session(s) to '{args.output}'.")
        else:
            print(json_output)

    except Exception as e:
        print(f"Error parsing PCAP file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
