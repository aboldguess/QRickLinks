"""
# QRickLinks Environment Bootstrap Script

This utility prepares local configuration for the QRickLinks project.  It copies
``.env.example`` to a suite of environment files used by both traditional
workflows (``.env``) and Vercel deployments (``.env.local``, ``.env.production``
and ``.vercel/.env.production.local``).  The helper generates
cryptographically secure secrets when requested and logs every action for easy
auditing.  The module is intentionally linear: helper functions handle argument
parsing, logging configuration and environment creation so contributors can
quickly understand each step when debugging setup issues.
"""

from __future__ import annotations

import argparse
import logging
import secrets
from pathlib import Path

ENV_TEMPLATE = Path(".env.example")
DEFAULT_SECRET = "change-this-secret-key"
ENV_VARIANTS: tuple[tuple[str, Path], ...] = (
    ("Primary .env", Path(".env")),
    ("Local overrides .env.local", Path(".env.local")),
    ("Production defaults .env.production", Path(".env.production")),
    (
        "Vercel CLI production env .vercel/.env.production.local",
        Path(".vercel") / ".env.production.local",
    ),
)


def configure_logging(level: str) -> None:
    """Initialise the root logger using the provided level name."""

    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO))


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the bootstrap helper."""

    parser = argparse.ArgumentParser(
        description=(
            "Create a populated .env file for QRickLinks, generating a secure "
            "SECRET_KEY if requested."
        )
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing .env file instead of leaving it untouched.",
    )
    parser.add_argument(
        "--generate-secret",
        action="store_true",
        help="Generate a new SECRET_KEY value using Python's secrets module.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Set the verbosity of the bootstrap script (DEBUG, INFO, etc.).",
    )
    return parser.parse_args()


def read_template() -> str:
    """Return the contents of ``.env.example`` or raise an informative error."""

    if not ENV_TEMPLATE.exists():
        raise FileNotFoundError(
            "The .env.example template is missing; run from the repository root."
        )
    return ENV_TEMPLATE.read_text(encoding="utf-8")


def build_secret(existing: str, should_replace: bool) -> str:
    """Return an appropriate SECRET_KEY value for the new environment file."""

    if should_replace or existing == DEFAULT_SECRET:
        return secrets.token_hex(32)
    return existing


def create_env_files(content: str, overwrite: bool) -> None:
    """Write environment files for local use and Vercel CLI integration."""

    for description, path in ENV_VARIANTS:
        if path.exists() and not overwrite:
            logging.info("Existing %s found; run with --force to overwrite.", path)
            continue

        if path.parent != Path("."):
            path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(content, encoding="utf-8")
        logging.info("%s written to %s", description, path)



def main() -> None:
    """Entry point that orchestrates the environment bootstrap process."""

    args = parse_args()
    configure_logging(args.log_level)

    try:
        template = read_template()
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        raise SystemExit(1) from exc

    lines = []
    for line in template.splitlines():
        if line.startswith("SECRET_KEY="):
            key = line.partition("=")[2]
            replacement = build_secret(key, args.generate_secret)
            lines.append(f"SECRET_KEY={replacement}")
        else:
            lines.append(line)

    create_env_files("\n".join(lines) + "\n", args.force)
    logging.info(
        "Bootstrap complete. Review .env (and its Vercel copies) to ensure Google OAuth and other settings are configured."
    )


if __name__ == "__main__":
    main()
