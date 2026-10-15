"""Synthetic security logs for demos, tests and benchmarks.

``watchpost generate-logs`` writes normal activity for a small fictional
company with several attacks hidden in it; see :mod:`watchpost.datagen.generator`.
"""

from watchpost.datagen.generator import (
    GeneratedFile,
    GeneratorConfig,
    GeneratorError,
    Manifest,
    generate,
)
from watchpost.datagen.scenarios import Scenario

__all__ = [
    "GeneratedFile",
    "GeneratorConfig",
    "GeneratorError",
    "Manifest",
    "Scenario",
    "generate",
]
