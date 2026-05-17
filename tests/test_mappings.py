import json

from aegislog.mappings import load_mapping_file


def test_load_mapping_file_json(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(
        json.dumps(
            {
                "fields": {
                    "timestamp": ["ts"],
                    "src_ip": ["client_ip"],
                    "message": ["log_message"],
                }
            }
        ),
        encoding="utf-8",
    )

    mapping = load_mapping_file(str(path))

    assert mapping == {
        "fields": {
            "timestamp": ["ts"],
            "src_ip": ["client_ip"],
            "message": ["log_message"],
        }
    }


def test_load_mapping_file_yaml(tmp_path):
    path = tmp_path / "mapping.yaml"
    path.write_text(
        """
fields:
  timestamp: ts
  src_ip: client_ip
  user: user_name
  message: log_message
""".strip(),
        encoding="utf-8",
    )

    mapping = load_mapping_file(str(path))

    assert mapping == {
        "fields": {
            "timestamp": ["ts"],
            "src_ip": ["client_ip"],
            "user": ["user_name"],
            "message": ["log_message"],
        }
    }