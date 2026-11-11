"""Detection data for the AI metadata audit.

These tables are matching rules only. They describe names a package's own metadata might
contain; they are not statements by this project about any tool.
"""

from __future__ import annotations

import re

# Names that identify a generation tool when they appear in a tool-type field.
UNAMBIGUOUS_TOOLS: tuple[str, ...] = (
    "stable diffusion",
    "stablediffusion",
    "midjourney",
    "dall-e",
    "dalle",
    "invokeai",
    "comfyui",
    "automatic1111",
    "novelai",
    "adobe firefly",
    "leonardo.ai",
    "chatgpt",
    "openai",
    "stability.ai",
)

# Names that are common words or have non-AI meanings, so a match is only a weak indicator.
AMBIGUOUS_TOOLS: tuple[str, ...] = ("firefly", "gemini", "claude", "copilot", "flux", "sdxl")

FREE_TEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bai[- ](?:generated|assisted|created|made)\b", re.I),
    re.compile(r"\b(?:generated|created|made) (?:with|using|by) (?:an? )?ai\b", re.I),
    re.compile(r"\bmidjourney\b|\bstable diffusion\b|\bdall[- ]?e\b", re.I),
)

BOOLEAN_KEYS = frozenset(
    {
        "aigenerated",
        "isaigenerated",
        "usesai",
        "aiassisted",
        "generatedbyai",
        "aicontent",
        "containsai",
        "aiused",
    }
)
DISCLOSURE_KEYS = frozenset(
    {"aidisclosure", "aistatement", "aiusage", "aitools", "aitoolsused", "aidisclosurestatement"}
)
TOOL_KEYS = frozenset(
    {"generator", "software", "creatortool", "generatedby", "tool", "createdwith", "softwareagent"}
)
FREE_TEXT_KEYS = frozenset({"description", "summary", "notes", "about", "comment", "readme"})

PNG_TOOL_KEYS = frozenset(
    {"invokeai_metadata", "sd-metadata", "sd_metadata", "dream", "fooocus_scheme"}
)

AI_SOURCE_TYPES = ("trainedalgorithmicmedia", "compositewithtrainedalgorithmicmedia")
AMBIGUOUS_SOURCE_TYPES = ("algorithmicmedia", "compositesynthetic")


def match_tool(value: str) -> str | None:
    """Return 'unambiguous', 'ambiguous' or None for a tool-field value."""
    low = value.lower()
    if any(name in low for name in UNAMBIGUOUS_TOOLS):
        return "unambiguous"
    if any(re.search(rf"\b{re.escape(n)}\b", low) for n in AMBIGUOUS_TOOLS):
        return "ambiguous"
    return None


def normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())
