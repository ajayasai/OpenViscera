"""Local administration. Never writes runtime data, credentials or keys into source control."""
import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path

from .domain import RuleError, canonical, require
from .evidence import check_database, encrypted_backup, restore_backup, verify_bundle
from .store import Store


def main(argv=None):
    parser = argparse.ArgumentParser(prog="openviscera")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Initialize an empty department; prompts for admin password")
    init.add_argument("--data", default="./var")
    init.add_argument("--admin", default="admin")
    init.add_argument("--department", default="department")
    demo = sub.add_parser("demo", help="Create synthetic cases with randomly generated demo credentials")
    demo.add_argument("--data", default="./demo-data")
    serve = sub.add_parser("serve", help="Serve the browser application")
    serve.add_argument("--data", default=os.environ.get("OV_DATA", "./var"))
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--origin", default=os.environ.get("OV_ORIGIN"))
    serve.add_argument("--insecure-local", action="store_true")
    verify = sub.add_parser("verify", help="Verify an evidence ZIP against a separately trusted public key")
    verify.add_argument("bundle")
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--expected-head")
    audit = sub.add_parser("audit", help="Replay database and emit an externally retainable signed checkpoint")
    audit.add_argument("--data", default="./var")
    audit.add_argument("--output", required=True)
    backup = sub.add_parser("backup", help="Encrypted, consistent database and signing-key backup")
    backup.add_argument("--data", default="./var")
    backup.add_argument("--output", required=True)
    restore = sub.add_parser("restore", help="Verify and restore an encrypted backup into a new directory")
    restore.add_argument("backup")
    restore.add_argument("--data", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            password = getpass.getpass("New admin password (14+ characters): ")
            require(password == getpass.getpass("Confirm password: "), "Passwords differ", 422)
            require(len(password) >= 14, "Password must be at least 14 characters", 422)
            store = Store.initialize(args.data)
            store.add_user(args.department, {"username": args.admin, "display_name": "Department administrator",
                                            "role": "admin", "password": password})
            print("Initialized. Create examiner, reviewer and coordinator accounts from the Administration screen.")
            print("Store public-key.txt separately; protect signing.key and the entire data directory.")
        elif args.command == "demo":
            from .demo import populate
            credentials = populate(Store.initialize(args.data))
            print("SYNTHETIC DEMONSTRATION ONLY. Random credentials (shown only here):")
            for username, password in credentials.items():
                print(f"{username}: {password}")
            print("Start with: openviscera serve --data " + args.data + " --insecure-local")
        elif args.command == "serve":
            import uvicorn
            from .app import create_app
            require(not args.insecure_local or args.host in {"127.0.0.1", "::1", "localhost"},
                    "Insecure local server must bind only to loopback")
            origin = args.origin or (f"http://127.0.0.1:{args.port}" if args.insecure_local else "https://localhost")
            app = create_app(args.data, origin, args.insecure_local)
            uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False, access_log=False)
        elif args.command == "verify":
            result = verify_bundle(Path(args.bundle).read_bytes(), Path(args.public_key).read_text(), args.expected_head)
            print(json.dumps(result, indent=2))
        elif args.command == "audit":
            store = Store(args.data)
            checkpoint = check_database(store)
            result = {"checkpoint": checkpoint, "signature": base64.b64encode(store.key.sign(canonical(checkpoint))).decode()}
            with Path(args.output).open("x") as stream:
                json.dump(result, stream, indent=2)
            print("Verified", len(checkpoint["heads"]), "cases. Retain checkpoint outside this deployment.")
        elif args.command == "backup":
            store = Store(args.data)
            password = getpass.getpass("Backup passphrase (14+ characters): ")
            require(password == getpass.getpass("Confirm passphrase: "), "Passphrases differ", 422)
            content = encrypted_backup(store, password)
            with Path(args.output).open("xb") as stream:
                stream.write(content)
            os.chmod(args.output, 0o600)
            print("Encrypted backup created. Protect its passphrase separately.")
        elif args.command == "restore":
            restore_backup(Path(args.backup).read_bytes(), getpass.getpass("Backup passphrase: "), args.data)
            print("Restored and verified. Existing login sessions were invalidated.")
        return 0
    except (RuleError, OSError, ValueError) as exc:
        print("Error:", str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
