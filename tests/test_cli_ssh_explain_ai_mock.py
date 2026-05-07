import json
import subprocess
import sys
from pathlib import Path


def test_explain_with_ai_analysis_json(tmp_path: Path) -> None:
    """
    Smoke test that SSH explain with --use-llm produces ai_analysis in JSON output.
    Writes to a temp file and reads it back instead of relying on stdout.
    """

    project_root = Path(__file__).resolve().parents[1]
    log_path = project_root / "data" / "loghub" / "SSH.log"
    output_path = tmp_path / "explain_ai.json"

    assert log_path.exists(), "Expected sample SSH log to exist for tests."

    cmd = [
        sys.executable,
        "-m",
        "aegislog.cli_ssh",
        "explain",
        str(log_path),
        "--log-type",
        "ssh_auth",
        "--first",
        "--use-llm",
        "--format",
        "json",
        "--output",
        str(output_path),
    ]

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if not output_path.exists():
        print("STDOUT:", completed.stdout)
        print("STDERR:", completed.stderr)
    assert output_path.exists(), "Expected JSON output file to be created."
    
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    # Legacy fields should still be present
    assert "incident" in payload
    assert "summary" in payload
    assert "local_explanation" in payload
    assert "llm_prompt" in payload
    assert "incident_evidence" in payload

    # New AI analysis should be present and structured
    ai = payload.get("ai_analysis")
    assert isinstance(ai, dict)

    for key in [
        "summary",
        "evidence",
        "hypothesis",
        "caveats",
        "next_steps",
        "playbook_slug",
        "playbook_notes",
    ]:
        assert key in ai