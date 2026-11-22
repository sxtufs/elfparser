#!/usr/bin/env python3
'''One-shot P1 migration: extract built-in plugins to assets and rewrite the
ViewModel to load them from assets instead of inline Kotlin strings.

What it does
------------
1. Reads ELFTraceViewModel.kt, extracts every raw-string trimIndent() block
   inside `val builtInJsons = listOf(...)`.
2. Validates each block with json.loads() and writes one file per plugin to
   app/src/main/assets/plugins/NN-<id>.json.
3. Rewrites ELFTraceViewModel.kt:
     - class ELFTraceViewModel : ViewModel()  ->  (app: Application) : AndroidViewModel(app)
     - adds `import android.app.Application` if missing
     - replaces the `val builtInJsons = listOf(...)` span with an asset loader.
4. Writes a .bak backup of the Kotlin file first.

Run from the repo root:
    python tools/extract_plugins.py

Pure stdlib. Works in Termux (pkg install python).
'''
import json
import re
import shutil
import sys
from pathlib import Path

KT = Path("app/src/main/java/io/elftrace/app/viewmodel/ELFTraceViewModel.kt")
OUT = Path("app/src/main/assets/plugins")

LOADER_BLOCK = '''        // Load plugin manifests from assets/plugins/*.json (P1 refactor:
        // previously an ~700-line inline listOf of raw JSON strings).
        val builtInJsons: List<String> = try {
            val names = application.assets.list("plugins")
                ?.filter { it.endsWith(".json") }
                ?.sorted()
                ?: emptyList()
            names.mapNotNull { name ->
                try {
                    application.assets.open("plugins/$name")
                        .bufferedReader().use { it.readText() }
                } catch (e: Exception) {
                    builtInLoadErrorsAccumulator.add(
                        "$name: ${e.message ?: e.javaClass.simpleName}"
                    )
                    null
                }
            }
        } catch (e: Exception) {
            builtInLoadErrorsAccumulator.add(
                "assets/plugins: ${e.message ?: e.javaClass.simpleName}"
            )
            emptyList()
        }'''


def trim_indent(s: str) -> str:
    lines = s.split("\n")
    while lines and lines[0].strip() == "":
        lines.pop(0)
    while lines and lines[-1].strip() == "":
        lines.pop()
    indents = [len(l) - len(l.lstrip(" \t")) for l in lines if l.strip()]
    min_ind = min(indents) if indents else 0
    return "\n".join((l[min_ind:] if len(l) >= min_ind else l.lstrip()) for l in lines)


def extract_raw_blocks(text: str):
    start = text.find("val builtInJsons = listOf(")
    if start == -1:
        raise SystemExit("ERROR: `val builtInJsons = listOf(` not found (already migrated?)")
    end_marker = text.find("val loaded = builtInJsons", start)
    if end_marker == -1:
        raise SystemExit("ERROR: `val loaded = builtInJsons` not found")
    region = text[start:end_marker]
    out = []
    idx = 0
    while True:
        i = region.find('"""', idx)
        if i == -1:
            break
        j = region.find('"""', i + 3)
        if j == -1:
            break
        body = region[i + 3:j]
        if ".trimIndent" in region[j + 3:j + 24]:
            out.append(trim_indent(body))
        idx = j + 3
    return out


def write_assets(blocks):
    OUT.mkdir(parents=True, exist_ok=True)
    # clear stale files from a previous run
    for old in OUT.glob("*.json"):
        old.unlink()
    for n, raw in enumerate(blocks, 1):
        raw = raw.strip()
        try:
            obj = json.loads(raw)
        except Exception as e:
            print(f"ERROR: plugin #{n} invalid JSON: {e}", file=sys.stderr)
            print(raw[:300], file=sys.stderr)
            sys.exit(1)
        pid = obj.get("id") or f"plugin{n}"
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(pid))
        fname = f"{n:02d}-{safe}.json"
        (OUT / fname).write_text(raw + "\n", encoding="utf-8")
        print(f"  asset: {fname:44s} id={pid}")


def rewrite_viewmodel(text: str) -> str:
    # 1) class declaration -> AndroidViewModel
    before = text
    text = text.replace(
        "class ELFTraceViewModel : ViewModel() {",
        "class ELFTraceViewModel(app: Application) : AndroidViewModel(app) {",
    )
    if text == before:
        print("WARN: class declaration not changed (already AndroidViewModel?)", file=sys.stderr)

    # 2) ensure required imports (Application + AndroidViewModel)
    if "import androidx.lifecycle.AndroidViewModel" not in text:
        text = text.replace(
            "import androidx.lifecycle.ViewModel",
            "import androidx.lifecycle.AndroidViewModel\nimport androidx.lifecycle.ViewModel",
            1,
        )
    if "import android.app.Application" not in text:
        text = text.replace(
            "import android.content.Context",
            "import android.app.Application\nimport android.content.Context",
            1,
        )

    # 3) replace the listOf(...) span with the asset loader.
    start = text.find("        val builtInJsons = listOf(")
    if start == -1:
        raise SystemExit("ERROR: listOf start not found (already migrated?)")
    close = text.find("\n        )\n", start)
    if close == -1:
        raise SystemExit("ERROR: listOf closing paren not found")
    end = close + len("\n        )")
    text = text[:start] + LOADER_BLOCK + text[end:]
    return text


def main():
    if not KT.exists():
        raise SystemExit(f"ERROR: not found: {KT} (run from repo root)")
    text = KT.read_text(encoding="utf-8")

    blocks = extract_raw_blocks(text)
    if not blocks:
        raise SystemExit("ERROR: extracted 0 plugins")
    print(f"Extracted {len(blocks)} plugins. Writing assets...")
    write_assets(blocks)

    bak = KT.with_suffix(KT.suffix + ".bak")
    shutil.copy2(KT, bak)
    print(f"Backup: {bak}")

    new_text = rewrite_viewmodel(text)
    KT.write_text(new_text, encoding="utf-8")
    print("Rewrote ELFTraceViewModel.kt (AndroidViewModel + asset loader).")
    print("\nDone. Now: ./gradlew :app:assembleDebug")


if __name__ == "__main__":
    main()
