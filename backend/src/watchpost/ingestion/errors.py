"""Exceptions raised while ingesting log files."""

from __future__ import annotations


class IngestionError(Exception):
    """Base class for ingestion failures that should be reported to the user."""


class ParseError(IngestionError):
    """A single line or record could not be parsed; it is counted and skipped."""


class UnsupportedFileError(IngestionError):
    """The file is not something the platform can ingest (binary, archive, ...)."""


class UploadTooLargeError(IngestionError):
    """An upload exceeded the configured size limit."""


class FormatDetectionError(IngestionError):
    """Automatic format detection could not identify a parser for the file."""
