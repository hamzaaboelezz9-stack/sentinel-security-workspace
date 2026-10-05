"""Export source through an explicit allowlist, without repository internals.

Usage: python scripts/package-source.py [--output /absolute/path/bundle.zip]
The ZIP is reproducible for the same source bytes, with fixed metadata.
"""
from argparse import ArgumentParser
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


def main():
    root = Path(__file__).resolve().parent.parent
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=root / "releases" / "sentinel-security-workspace.zip")
    output = parser.parse_args().output.resolve()
    documents = ("README.md", "LICENSE", "GITHUB_DESCRIPTION.txt", ".gitignore",
                 ".gitattributes", "package.json", "package-lock.json", "serve.cjs")
    files = [root / name for name in documents]
    # Never walk .git, node_modules, .env or generated release directories.
    suffixes = {".html", ".js", ".cjs", ".css", ".txt", ".md", ".json", ".yml", ".py"}
    for folder in ("dist", "tests", "scripts", "docs", ".github/workflows"):
        for path in (root / folder).rglob("*"):
            if path.is_symlink() or not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix in suffixes or path.name == "_headers":
                files.append(path)
    if any(not path.is_file() or path.is_symlink() for path in files):
        raise ValueError("Required source file is missing or is a symbolic link.")
    if output in files:
        raise ValueError("Output must not overwrite a source file.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(set(files)):
            member = ZipInfo("sentinel-security-workspace/" + path.relative_to(root).as_posix(),
                             date_time=(2026, 1, 1, 0, 0, 0))
            member.compress_type = ZIP_DEFLATED
            member.external_attr = 0o100644 << 16
            archive.writestr(member, path.read_bytes(), compresslevel=9)
    print(f"Source bundle: {output}; {len(set(files))} files; {output.stat().st_size:,} bytes")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"Cannot package source: {error}") from None
