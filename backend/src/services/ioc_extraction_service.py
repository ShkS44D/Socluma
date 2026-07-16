from __future__ import annotations
import re
from typing import Dict, Any, List, Tuple, Optional, Set
from src.models.sqlalchemy import IndicatorType


class IOCExtractionService:
    def __init__(self):
        # Valid IPv4 pattern
        self.ipv4_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )

        # Valid IPv6 pattern (simplified but functional)
        self.ipv6_pattern = re.compile(
            r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
            r"^::$|"
            r"^:(?::[0-9a-fA-F]{1,4}){1,7}$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|"
            r"^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$"
        )

        # URL pattern - MUST start with http:// or https://
        self.url_pattern = re.compile(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[^\s]*)?"
        )

        # Domain pattern - valid domain with TLD, not ending with common extensions
        self.domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
        )

        # Hash patterns
        self.md5_pattern = re.compile(r"^[a-fA-F0-9]{32}$")
        self.sha1_pattern = re.compile(r"^[a-fA-F0-9]{40}$")
        self.sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")

        # Common executable extensions to ignore
        self.executable_extensions: Set[str] = {
            ".exe",
            ".dll",
            ".sys",
            ".bat",
            ".ps1",
            ".cmd",
            ".com",
            ".scr",
            ".pif",
            ".vbs",
            ".vbe",
        }

        # Common process names to ignore
        self.common_processes: Set[str] = {
            "powershell",
            "powershell.exe",
            "cmd",
            "cmd.exe",
            "notepad",
            "notepad.exe",
            "explorer",
            "explorer.exe",
            "chrome",
            "chrome.exe",
            "firefox",
            "firefox.exe",
            "edge",
            "edge.exe",
            "svchost",
            "svchost.exe",
            "taskmgr",
            "taskmgr.exe",
            "calc",
            "calc.exe",
        }

    def is_valid_ip(self, value: str) -> bool:
        value = value.strip()
        return bool(self.ipv4_pattern.match(value) or self.ipv6_pattern.match(value))

    def is_valid_url(self, value: str) -> bool:
        value = value.strip()
        return bool(self.url_pattern.match(value))

    def is_valid_domain(self, value: str) -> bool:
        value = value.strip()
        # Check basic pattern
        if not self.domain_pattern.match(value):
            return False
        # Check if it's a process name or executable
        lower_value = value.lower()
        if lower_value in self.common_processes:
            return False
        for ext in self.executable_extensions:
            if lower_value.endswith(ext):
                return False
        return True

    def is_valid_hash(self, value: str) -> Tuple[bool, Optional[str]]:
        value = value.strip()
        if self.md5_pattern.match(value):
            return True, "md5"
        if self.sha1_pattern.match(value):
            return True, "sha1"
        if self.sha256_pattern.match(value):
            return True, "sha256"
        return False, None

    def extract_from_string(self, text: str) -> List[Tuple[IndicatorType, str]]:
        """Extract IOCs from a string, with proper validation and filtering"""
        iocs: List[Tuple[IndicatorType, str]] = []
        # Split string into tokens for more precise extraction
        tokens = re.split(r'[\s,;]+', text.strip())

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            # Check for URL first (more specific than domain)
            if self.is_valid_url(token):
                iocs.append((IndicatorType.URL, token))
                continue

            # Check for IP address
            if self.is_valid_ip(token):
                iocs.append((IndicatorType.IP, token))
                continue

            # Check for domain
            if self.is_valid_domain(token):
                iocs.append((IndicatorType.DOMAIN, token))
                continue

            # Check for hash
            is_hash, _ = self.is_valid_hash(token)
            if is_hash:
                iocs.append((IndicatorType.HASH, token))
                continue

        return iocs

    def extract_from_dict(
        self, data: Dict[str, Any], keys_to_check: Optional[List[str]] = None
    ) -> List[Tuple[IndicatorType, str]]:
        """Extract IOCs from a dictionary by checking all string values"""
        iocs: List[Tuple[IndicatorType, str]] = []
        if not data:
            return iocs

        def _extract_recursive(obj: Any):
            if isinstance(obj, dict):
                for value in obj.values():
                    _extract_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    _extract_recursive(item)
            elif isinstance(obj, str):
                extracted = self.extract_from_string(obj)
                iocs.extend(extracted)

        _extract_recursive(data)
        # Deduplicate
        return list(dict.fromkeys(iocs))


ioc_extraction_service = IOCExtractionService()
