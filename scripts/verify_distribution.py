"""Smoke-test built packages without relying on a checkout or network access.

Before running, build with ``python -m build`` and download source-build wheels:
``python -m pip download --only-binary=:all: --dest /tmp/phishlens-build-deps
"setuptools>=68" wheel``. Then run this script with ``--build-deps`` pointing to
that directory. Package installs themselves always use ``--no-index``.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv


FIXTURE_NAMES = (
    "clean_newsletter.eml",
    "dmarc_spoof.eml",
    "anchor_mismatch.eml",
    "suspicious_attachment.eml",
    "lookalike_domain.eml",
    "zh_fake_police.eml",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(command: list[str], cwd: Path, *, expected: int = 0) -> str:
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE"):
        environment.pop(name, None)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    result = subprocess.run(command, cwd=cwd, env=environment,
                            stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, encoding="utf-8", timeout=120)
    require(result.returncode == expected,
            f"Command returned {result.returncode}, expected {expected}: {command!r}\n"
            f"{result.stdout}\n{result.stderr}")
    return result.stdout


def read_fixtures(sdist: Path, destination: Path) -> dict[str, Path]:
    """Copy known fixture bytes, without extracting archive paths or links."""
    fixtures = {}
    with tarfile.open(sdist, "r:gz") as archive:
        for name in FIXTURE_NAMES:
            matches = [member for member in archive.getmembers()
                       if PurePosixPath(member.name).parts[1:] == ("tests", "fixtures", name)]
            require(len(matches) == 1, f"Source distribution must include one fixture: {name}")
            member = matches[0]
            require(member.isfile() and 0 < member.size <= 1024 * 1024,
                    f"Invalid fixture in source distribution: {name}")
            stream = archive.extractfile(member)
            require(stream is not None, f"Cannot read fixture: {name}")
            with stream:
                data = stream.read()
            path = destination / name
            path.write_bytes(data)
            fixtures[name] = path
    return fixtures


def verify_package(artifact: Path, working: Path, build_deps: Path,
                   fixtures: dict[str, Path], version: str) -> None:
    environment = working / ("wheel-env" if artifact.suffix == ".whl" else "sdist-env")
    venv.EnvBuilder(with_pip=True).create(environment)
    bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    cli = bin_dir / ("phishlens.exe" if os.name == "nt" else "phishlens")
    pip = [str(python), "-I", "-m", "pip", "--isolated", "install", "--no-index"]
    if artifact.suffix != ".whl":
        run(pip + ["--find-links", str(build_deps), "setuptools>=68", "wheel"], working)
    run(pip + ["--no-deps", "--no-build-isolation", str(artifact)], working)

    # Confirm that both metadata and the module come from the installed artifact.
    installed = json.loads(run([str(python), "-I", "-c",
        "import json, phishlens; from importlib.metadata import version; "
        "print(json.dumps({'metadata_version': version('phishlens'), "
        "'module_version': phishlens.__version__, 'path': phishlens.__file__}))"], working))
    require(installed["metadata_version"] == version and installed["module_version"] == version,
            f"Installed version does not match pyproject.toml: {installed}")
    require(Path(installed["path"]).resolve().is_relative_to(environment.resolve()),
            f"Package loaded from outside fresh virtual environment: {installed['path']}")
    require(run([str(cli), "--version"], working).strip() == f"phishlens {version}",
            "Installed command reports an incorrect version")
    require(run([str(python), "-I", "-m", "phishlens", "--version"], working).strip()
            == f"phishlens {version}", "Module command reports an incorrect version")

    clean = str(fixtures["clean_newsletter.eml"])
    require("LOW RISK" in run([str(cli), "analyze", clean], working),
            "Plain-text report is missing the clean verdict")
    clean_json = json.loads(run([str(cli), "analyze", clean, "--json", "--fail-on", "suspicious"],
                                working))
    require(clean_json["level"] == "low" and clean_json["score"] == 0,
            "Clean fixture should score zero and not fail the risk threshold")
    for name, fixture in fixtures.items():
        if name == "clean_newsletter.eml":
            continue
        output = run([str(cli), "analyze", str(fixture), "--json", "--fail-on", "high"],
                     working, expected=2)
        report = json.loads(output)
        require(report["level"] == "high" and report["findings"],
                f"Phishing fixture should produce a high-risk JSON report: {name}")
    print(f"Verified {artifact.name}: version, imports, text/JSON reports and risk exit codes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--build-deps", type=Path, required=True,
                        help="directory containing predownloaded setuptools and wheel dependencies")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    with (project / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    artifacts = args.dist_dir.resolve()
    wheels = list(artifacts.glob("phishlens-*.whl"))
    sdists = list(artifacts.glob("phishlens-*.tar.gz"))
    require(len(wheels) == 1 and len(sdists) == 1,
            f"Expected one wheel and one source distribution in {artifacts}; clean and rebuild it")
    require(args.build_deps.is_dir(), f"Missing offline build dependencies: {args.build_deps}")
    with tempfile.TemporaryDirectory(prefix="phishlens-distribution-") as directory:
        working = Path(directory).resolve()
        require(not working.is_relative_to(project),
                "Temporary directory is inside checkout; set TMPDIR outside the repository")
        fixtures = read_fixtures(sdists[0], working)
        for artifact in (wheels[0], sdists[0]):
            verify_package(artifact, working, args.build_deps.resolve(), fixtures, version)
    print("All distribution checks passed; no packages were published.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, tarfile.TarError, subprocess.TimeoutExpired) as error:
        print(f"Distribution verification failed: {error}", file=sys.stderr)
        sys.exit(1)
