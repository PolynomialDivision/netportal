#!/usr/bin/env python3
"""Export netportal/i18n.py (the Python version's texts) to rust/crates/netportal-core/i18n.json,
the one source of the Rust version's translations (docs/ARCHITECTURE.md, "Rules").

    python3 rust/tools/export_i18n.py            write the file
    python3 rust/tools/export_i18n.py --stdout   print it (the Rust test compares)

Contents: "languages" (in i18n.TEXT's order), "texts" (lang -> key -> str or list of str, the
merged TEXT dicts in their order), "tables" (every other module-level constant of i18n.py that
is plain data: the code tuples, PLATFORM_LABEL, the evidence tables, the thresholds, the
number separators as "SEPARATORS", Format.NONE as "FORMAT_NONE"). Python has no plural forms
(the texts avoid them), so there are none here either. Only netportal/i18n.py is imported; it
imports nothing from the package at module level.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

RUST = Path(__file__).resolve().parent.parent
REPO = RUST.parent
SOURCE = REPO / "netportal" / "i18n.py"
TARGET = RUST / "crates" / "netportal-core" / "i18n.json"
RAW_DICTS = {"TEXT", "DASHBOARD_TEXT", "TELEMETRY_TEXT", "PRESENCE_TEXT"}


def load():
    spec = importlib.util.spec_from_file_location("netportal_i18n_export", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plain(value):
    """value as JSON data (tuples as lists), or raise TypeError."""
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        return {k: plain(v) for k, v in value.items()}
    raise TypeError(type(value).__name__)


def export():
    i18n = load()
    texts = {}
    for lang, table in i18n.TEXT.items():
        texts[lang] = {}
        for key, value in table.items():
            if isinstance(value, str):
                texts[lang][key] = value
            elif isinstance(value, list) and all(isinstance(v, str) for v in value):
                texts[lang][key] = list(value)
            else:
                raise TypeError("%s.%s is neither a text nor a list of texts" % (lang, key))
    tables = {}
    for name, value in vars(i18n).items():
        if not re.fullmatch(r"_?[A-Z][A-Z0-9_]*", name) or name in RAW_DICTS:
            continue
        try:
            tables[name.lstrip("_")] = plain(value)
        except TypeError:
            continue
    tables["FORMAT_NONE"] = i18n.Format.NONE
    data = {"source": "netportal/i18n.py", "languages": list(i18n.TEXT), "texts": texts, "tables": tables}
    return json.dumps(data, ensure_ascii=False, indent=1) + "\n"


def main(argv):
    text = export()
    if "--stdout" in argv:
        sys.stdout.write(text)
    else:
        TARGET.write_text(text, encoding="utf-8")
        print("wrote %s" % TARGET.relative_to(REPO))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
