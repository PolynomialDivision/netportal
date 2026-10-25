"""Command line: python -m netportal <command>

  init-db                       create/upgrade the schema (also done by the web app at start)
  offboard [--every SECONDS]    reconcile with Authentik once, or forever (the sidecar)
  collect [--once] [--jobs a,b] the collector (container netportal-collect): Loki/Prometheus ->
                                connection events, incidents, daily rollups, retention; forever,
                                or every selected job once
  job NAME                      one collector job once (unifi_events, incidents, rollup, prune)
  pki --out DIR [--name NAME] --server-name FQDN
                                the PKI ceremony: root (offline), device CA, RADIUS server
                                certificate as PEM files; run on an admin's machine, not the server
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path


def cmd_init_db(args):
    from . import config, registry
    settings = config.load()
    with registry.connect(settings.database_url) as db:
        registry.init(db, settings.policies)
    print("schema ready")


HEARTBEAT = os.environ.get("NETPORTAL_HEARTBEAT", "/tmp/netportal-offboard.heartbeat")


def cmd_offboard(args):
    """Reconcile once, or forever with --every. After every round (also a failed one: the
    metric shows the age of the last success) the heartbeat file is touched, so the
    container's healthcheck can tell a living sidecar from a hung one."""
    from . import config, offboarding
    settings = config.load()
    while True:
        failed = False
        try:
            offboarding.run(settings)
        except Exception:  # noqa: BLE001 (keep the loop)
            logging.exception("offboarding failed")
            failed = True
        Path(HEARTBEAT).touch()
        if not args.every:
            return 1 if failed else 0
        time.sleep(args.every)


def cmd_collect(args):
    """The collector's scheduler (netportal.collect); its settings need no web secrets."""
    from .collect import jobs, scheduler, settings as collect_settings
    settings = collect_settings.load()
    selected = jobs.select(args.jobs)
    sched = scheduler.Scheduler(settings, selected)
    scheduler.install_signal_handlers(sched.stop)
    return sched.run_once() if args.once else sched.run_forever()


def cmd_job(args):
    from .collect import jobs, scheduler, settings as collect_settings
    settings = collect_settings.load()
    sched = scheduler.Scheduler(settings, jobs.select(args.name))
    scheduler.install_signal_handlers(sched.stop)
    return sched.run_once()


def cmd_pki(args):
    from . import pki
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    root = pki.make_ca("%s Network Root" % args.name, days=7300, path_length=1)
    device_ca = pki.make_ca("%s Device CA" % args.name, issuer=root, days=3650, path_length=0)
    server = pki.server_cert(root, args.server_name, days=825)

    def write(name, data, secret=False):
        path = out / name
        path.write_bytes(data)
        path.chmod(0o600 if secret else 0o644)

    write("root.pem", root.cert_pem())
    write("root.key", root.key_pem(), secret=True)            # offline: password manager, never the server
    write("device-ca.pem", device_ca.cert_pem())
    write("device-ca.key", device_ca.key_pem(), secret=True)  # vault -> netportal only
    write("device-ca-chain.pem", device_ca.cert_pem() + root.cert_pem())   # FreeRADIUS ca_file
    write("radius-server.pem", server.cert_pem())
    write("radius-server.key", server.key_pem(), secret=True)  # vault -> FreeRADIUS only
    print("PKI written to %s; device CA DN for FreeRADIUS check_cert_issuer: /CN=%s Device CA"
          % (out, args.name))
    return 0


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="netportal")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db").set_defaults(func=cmd_init_db)
    p = sub.add_parser("offboard")
    p.add_argument("--every", type=int, default=0)
    p.set_defaults(func=cmd_offboard)
    p = sub.add_parser("collect")
    p.add_argument("--once", action="store_true", help="run every selected job once, then exit")
    p.add_argument("--jobs", default="", help="comma-separated job names (default: all)")
    p.set_defaults(func=cmd_collect)
    p = sub.add_parser("job")
    p.add_argument("name")
    p.set_defaults(func=cmd_job)
    p = sub.add_parser("pki")
    p.add_argument("--out", required=True)
    p.add_argument("--name", default="Scharni")
    p.add_argument("--server-name", required=True)
    p.set_defaults(func=cmd_pki)
    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
