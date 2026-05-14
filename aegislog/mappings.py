import json
from pathlib import Path
from typing import Any


def load_mapping_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}

    mapping_path = Path(path)
    suffix = mapping_path.suffix.lower()
    text = mapping_path.read_text(encoding="utf-8")

    if suffix == ".json":
        data = json.loads(text)
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "YAML mapping files require PyYAML. Install it with: pip install pyyaml"
            ) from exc
        data = yaml.safe_load(text)
    else:
        raise ValueError(f"Unsupported mapping file format: {mapping_path.suffix}")

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValueError("Mapping file must contain an object at the top level.")

    fields = data.get("fields", data)

    if not isinstance(fields, dict):
        raise ValueError("Mapping file 'fields' value must be an object.")

    normalized: dict[str, str] = {}
    for dest, src in fields.items():
        if not isinstance(dest, str) or not isinstance(src, str):
            raise ValueError("All mapping entries must be string-to-string pairs.")
        normalized[dest] = src

    return normalized