"""Module entry point for environments where the console-script directory is not on PATH."""

from .cli import main


raise SystemExit(main())
