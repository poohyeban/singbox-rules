"""Resolve a complete v2fly category include tree from one archive snapshot."""
import io
import re
import zipfile

from .model import InvalidSource, v2fly


def google_domains(data: bytes, category: str = "google"):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        roots = [n[:-len("data/google")] for n in archive.namelist()
                 if n.endswith("/data/google")]
        if len(roots) != 1:
            raise InvalidSource("Expected one v2fly data root")
        prefix = roots[0] + "data/"
        sources, visiting = {}, set()

        def resolve(name):
            if not re.fullmatch(r"[a-z0-9_-]+", name):
                raise InvalidSource("Invalid v2fly include name")
            if name in visiting:
                raise InvalidSource("Cyclic v2fly include")
            if name in sources:
                return sources[name]
            try:
                info = archive.getinfo(prefix + name)
            except KeyError as error:
                raise InvalidSource("Missing v2fly include: " + name) from error
            if info.file_size > 2 * 1024 * 1024:
                raise InvalidSource("Oversized v2fly category")
            visiting.add(name)
            local, rules = [], set()
            for raw in archive.read(info).decode("utf-8-sig").splitlines():
                line = re.split(r"\s+#", raw.strip(), maxsplit=1)[0]
                if line.startswith("#"):
                    continue
                if line.startswith("include:"):
                    # Reject new filtered include syntax rather than silently
                    # broadening or narrowing the upstream selection.
                    rules |= resolve(line[len("include:"):])
                elif line:
                    local.append(line)
            if local:
                rules |= v2fly("\n".join(local))
            if not rules:
                raise InvalidSource("Empty v2fly category: " + name)
            visiting.remove(name)
            sources[name] = rules
            return rules

        rules = resolve(category)
        return rules, sorted(sources)
