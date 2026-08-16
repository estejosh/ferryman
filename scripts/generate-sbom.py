#!/usr/bin/env python3
"""Generate a CycloneDX 1.4 SBOM from the workspace's Cargo metadata.

No third-party tool required: `cargo metadata` already resolves the full
dependency graph; this restates it in CycloneDX component form.

Usage:
    python3 scripts/generate-sbom.py > sbom.cdx.json

`cargo cyclonedx` produces the same artifact if you prefer a maintained tool.
"""
import json
import subprocess

metadata = json.loads(
    subprocess.check_output(["cargo", "metadata", "--format-version", "1"])
)

components = []
for package in metadata.get("packages", []):
    name = package["name"]
    version = package["version"]
    source = package.get("source") or ""
    if source.startswith("registry+"):
        # crates.io registry packages get a standard cargo purl.
        purl = f"pkg:cargo/{name}@{version}"
    else:
        # Local path dependencies (workspace members) and git deps.
        purl = f"pkg:generic/{name}@{version}"
    components.append(
        {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        }
    )

components.sort(key=lambda c: (c["name"], c["version"]))

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": components,
}
print(json.dumps(sbom, indent=2))
