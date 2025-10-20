#!/usr/bin/env python3
"""# QRickLinks Vercel Deployment Preparation Script

This script automates the routine steps required to bootstrap a brand new
Vercel deployment for the QRickLinks project.  It is designed to be safe to run
on Windows, Linux and macOS, guiding the operator through environment file
creation, Vercel CLI installation, project linking and environment variable
synchronisation.  Every operation is logged so troubleshooting remains
straightforward and contributors can audit the performed actions at a glance.

High level workflow:

1. Verify the repository looks complete and ensure local environment files exist
   by delegating to :mod:`bootstrap_qricklinks_environment`.
2. Confirm the Vercel CLI is available (optionally installing it with ``npm``)
   and make sure the operator is logged in.
3. Link the current working tree to a Vercel project, optionally honouring
   command line arguments that pre-select the organisation and project names.
4. Push variables defined in ``.env.production`` to the Vercel environment so
   the serverless function has the configuration it needs.
5. Provide a concise checklist of the next manual actions, such as running a
   deployment or configuring DNS.

The helper intentionally keeps every subprocess call visible to the user.  This
ensures interactive prompts from the Vercel CLI (for example ``vercel login`` or
``vercel link``) function exactly as they would when run manually, while still
recording a structured log of progress.
"""

from __future__ import annotations

import argparse
import logging
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

REPO_SENTINEL = Path("qricklinks_app.py")
DEFAULT_ENV_FILE = Path(".env.production")
BOOTSTRAP_SCRIPT = Path("bootstrap_qricklinks_environment.py")


def configure_logging(level: str) -> None:
    """Initialise structured logging for the script."""

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="[%(levelname)s] %(message)s",
    )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    """Define and parse command line arguments for the helper."""

    parser = argparse.ArgumentParser(
        description=(
            "Prepare the QRickLinks repository for a brand new Vercel "
            "deployment, including CLI setup and environment syncing."
        )
    )
    parser.add_argument(
        "--project-name",
        help="Optional Vercel project slug to use when linking.",
    )
    parser.add_argument(
        "--org-slug",
        help=(
            "Optional Vercel organisation slug. Providing this removes one "
            "interactive question during `vercel link`."
        ),
    )
    parser.add_argument(
        "--skip-cli-install",
        action="store_true",
        help=(
            "Do not attempt to install the Vercel CLI automatically even if "
            "it is missing."
        ),
    )
    parser.add_argument(
        "--skip-env-sync",
        action="store_true",
        help="Skip pushing .env.production values to Vercel.",
    )
    parser.add_argument(
        "--include-preview",
        action="store_true",
        help=(
            "Also push configuration to Vercel's preview environment. "
            "Production is always synchronised unless --skip-env-sync is "
            "used."
        ),
    )
    parser.add_argument(
        "--include-development",
        action="store_true",
        help="Push configuration to Vercel's development environment as well.",
    )
    parser.add_argument(
        "--force-env-bootstrap",
        action="store_true",
        help="Regenerate environment files even when they already exist.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Set the verbosity of output (DEBUG, INFO, WARNING, ERROR).",
    )
    return parser.parse_args(argv)


def ensure_repository_structure() -> None:
    """Abort with a helpful message if the script is not run from the repo."""

    if not REPO_SENTINEL.exists():
        logging.error(
            "Repository sentinel %s not found. Run this script from the repo root.",
            REPO_SENTINEL,
        )
        raise SystemExit(1)
    logging.debug("Repository sentinel %s located.", REPO_SENTINEL)


def bootstrap_environment(force: bool) -> None:
    """Create local environment files by invoking the bootstrap helper."""

    if not BOOTSTRAP_SCRIPT.exists():
        logging.error("Bootstrap script %s is missing.", BOOTSTRAP_SCRIPT)
        raise SystemExit(1)

    command = [
        sys.executable,
        str(BOOTSTRAP_SCRIPT),
        "--generate-secret",
    ]
    if force:
        command.append("--force")

    logging.info("Ensuring local environment files exist via %s", BOOTSTRAP_SCRIPT)
    subprocess.check_call(command)


def check_binary_available(binary: str) -> bool:
    """Return True when the provided executable is available on PATH."""

    available = shutil.which(binary) is not None
    logging.debug("Binary %s availability: %s", binary, available)
    return available


def ensure_vercel_cli_installed(skip_install: bool) -> None:
    """Install the Vercel CLI using npm when necessary."""

    if check_binary_available("vercel"):
        logging.debug("Vercel CLI already present on PATH.")
        return

    if skip_install:
        logging.error(
            "Vercel CLI not found and --skip-cli-install was supplied. Install "
            "the CLI manually (npm install --global vercel) and re-run the script."
        )
        raise SystemExit(1)

    if not check_binary_available("npm"):
        logging.error(
            "npm is required to install the Vercel CLI automatically but was not "
            "found. Install Node.js from https://nodejs.org/ first or rerun the "
            "script with --skip-cli-install after manual installation."
        )
        raise SystemExit(1)

    logging.info("Installing Vercel CLI via npm. This may require administrative privileges.")
    subprocess.check_call(["npm", "install", "--global", "vercel"])

    if not check_binary_available("vercel"):
        logging.error("Vercel CLI installation appeared to succeed but the binary is still missing.")
        raise SystemExit(1)


def ensure_vercel_login() -> None:
    """Prompt the user to log in to Vercel when necessary."""

    logging.info("Verifying Vercel authentication status.")
    whoami = subprocess.run(["vercel", "whoami"], capture_output=True, text=True)
    if whoami.returncode == 0:
        logging.info("Already logged in as %s", whoami.stdout.strip())
        return

    logging.warning(
        "Not logged in to Vercel CLI. Launching interactive login flow now."
    )
    subprocess.check_call(["vercel", "login"])

    whoami = subprocess.run(["vercel", "whoami"], capture_output=True, text=True, check=False)
    if whoami.returncode != 0:
        logging.error("Login did not complete successfully. Rerun the script once authenticated.")
        raise SystemExit(1)

    logging.info("Authentication confirmed for %s", whoami.stdout.strip())


def link_project(project_name: str | None, org_slug: str | None) -> None:
    """Ensure the working tree is linked to a Vercel project."""

    project_file = Path(".vercel") / "project.json"
    if project_file.exists():
        logging.info("Existing Vercel project link found at %s", project_file)
        return

    logging.info(
        "Linking the repository to a Vercel project. Follow any interactive prompts."
    )
    command = ["vercel", "link"]
    if project_name:
        command.extend(["--project", project_name])
    if org_slug:
        command.extend(["--org", org_slug])
    subprocess.check_call(command)


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE environment file into a dictionary."""

    if not path.exists():
        logging.error("Environment file %s not found.", path)
        raise SystemExit(1)

    env_vars: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            logging.warning("Skipping malformed line in %s: %s", path, stripped)
            continue
        key, value = stripped.split("=", 1)
        env_vars[key.strip()] = value.strip()
    logging.debug("Loaded %d variables from %s", len(env_vars), path)
    return env_vars


def push_env_variables(env: dict[str, str], environment: str) -> None:
    """Send variables to the specified Vercel environment."""

    for key, value in env.items():
        logging.info("Pushing %s to Vercel %s environment", key, environment)
        process = subprocess.run(
            ["vercel", "env", "add", key, environment],
            input=f"{value}\n".encode("utf-8"),
            capture_output=True,
        )
        if process.returncode != 0:
            stderr = process.stderr.decode("utf-8", errors="ignore")
            logging.error(
                "Failed to push %s to %s. Output: %s", key, environment, stderr.strip()
            )
            raise SystemExit(1)


def sync_environment_variables(include_preview: bool, include_development: bool) -> None:
    """Coordinate pushing environment variables to Vercel."""

    env_vars = load_env_file(DEFAULT_ENV_FILE)

    push_env_variables(env_vars, "production")
    if include_preview:
        push_env_variables(env_vars, "preview")
    if include_development:
        push_env_variables(env_vars, "development")


def summarise_next_steps() -> None:
    """Print a helpful checklist for the operator."""

    message = "\n".join(
        [
            "Next steps:",
            "  1. Review https://vercel.com/dashboard to confirm the project link.",
            "  2. Run `vercel deploy --prod` once you are ready for a production deployment.",
            "  3. Configure any custom domains under Project Settings → Domains if required.",
            "  4. Monitor the first build to ensure the serverless function boots correctly.",
        ]
    )
    logging.info("\n%s", message)


def main(argv: Iterable[str] | None = None) -> None:
    """Script entry point coordinating the deployment preparation flow."""

    args = parse_args(argv)
    configure_logging(args.log_level)

    ensure_repository_structure()
    bootstrap_environment(force=args.force_env_bootstrap)
    ensure_vercel_cli_installed(skip_install=args.skip_cli_install)
    ensure_vercel_login()
    link_project(args.project_name, args.org_slug)

    if not args.skip_env_sync:
        sync_environment_variables(
            include_preview=args.include_preview,
            include_development=args.include_development,
        )
    else:
        logging.info("Skipping environment synchronisation as requested.")

    summarise_next_steps()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        command = " ".join(shlex.quote(part) for part in exc.cmd) if exc.cmd else "<unknown>"
        logging.error("Command failed: %s", command)
        raise SystemExit(exc.returncode) from exc
