# Third-party software distributed with Ferryman

Ferryman's container image bundles the components below. Everything here is included
**unmodified**; Ferryman calls them as separate programs and configures them over their
own interfaces.

---

## Syncthing

- **Project:** Syncthing — continuous file synchronisation
- **Source:** https://github.com/syncthing/syncthing
- **Licence:** Mozilla Public License 2.0 (MPL-2.0)
- **Licence text in the image:** `/usr/share/licenses/syncthing/LICENSE`
- **How it is used:** the official upstream release binary is placed in the image and
  run as a subprocess. It is configured through its REST API. **No Syncthing source
  file is modified**, so no MPL-2.0 source-disclosure obligation is triggered for
  Ferryman's own code. If a Ferryman contributor ever patches a Syncthing file, that
  file's changes must be published under MPL-2.0 — so don't: wrap it, don't fork it.
- **Name and logo:** "Syncthing" is used only to identify the bundled software. The
  Syncthing name and logo are not used to brand Ferryman or to suggest endorsement.

Ferryman is not affiliated with the Syncthing project.

### Running without the bundled copy

If you already run Syncthing, do not run a second one against the same folder — two
live sync engines on one folder cause conflict loops. Start the container with
`FERRYMAN_SYNCTHING=external` and point it at your existing instance.

---

## Debian base image

- **Source:** https://www.debian.org/
- **Licence:** individual packages under their own licences; see
  `/usr/share/doc/*/copyright` inside the image.
- **How it is used:** unmodified `debian:bookworm-slim` base plus `ca-certificates`
  and `tini`.

## tini

- **Source:** https://github.com/krallin/tini
- **Licence:** MIT
- **How it is used:** unmodified, as PID 1, to reap child processes. Ferryman
  supervises Syncthing as a child, so zombie reaping matters.

---

## Verifying for yourself

```sh
podman run --rm --entrypoint /bin/sh ghcr.io/estejosh/ferryman:latest \
  -c 'ls /usr/share/licenses; cat /usr/share/licenses/THIRD_PARTY.md'
```

Ferryman's own licence is at `/usr/share/licenses/ferryman/LICENSE`.
