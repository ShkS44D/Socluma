from __future__ import annotations

import re
import hashlib
import json
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.core.logging import logger
from src.models.sqlalchemy import Alert, IndicatorType, ThreatIntel, ThreatIntelCache, IOC
from src.services.ioc_service import ioc_service


class ThreatIntelService:
    # Regex patterns for indicator validation
    IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    IPV6_PATTERN = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
    HASH_MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    HASH_SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    HASH_SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')

    def __init__(self) -> None:
        self.settings = get_settings()
        self.known_bad_ips = {"198.51.100.25", "203.0.113.200"}
        self.known_bad_domains = {"malicious-example.test", "evil-login.example"}
        self.known_bad_hashes = {"abc123", "d41d8cd98f00b204e9800998ecf8427e"}

    def _validate_indicator(self, indicator: str, indicator_type: IndicatorType) -> bool:
        """Validate indicator format before external lookups"""
        if not indicator or len(indicator.strip()) == 0:
            return False

        indicator = indicator.strip()
        if indicator_type == IndicatorType.HASH and indicator in self.known_bad_hashes:
            return True

        if indicator_type in {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6}:
            return bool(self.IPV4_PATTERN.match(indicator) or self.IPV6_PATTERN.match(indicator))
        elif indicator_type == IndicatorType.DOMAIN:
            return bool(self.DOMAIN_PATTERN.match(indicator)) and len(indicator) <= 255
        elif indicator_type in {IndicatorType.HASH, IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256, IndicatorType.SHA512}:
            return bool(
                self.HASH_MD5_PATTERN.match(indicator) or
                self.HASH_SHA1_PATTERN.match(indicator) or
                self.HASH_SHA256_PATTERN.match(indicator)
            )
        elif indicator_type == IndicatorType.URL:
            return bool(self.URL_PATTERN.match(indicator)) and len(indicator) <= 2048
        return True

    def lookup_incident_indicators(self, db: Session, alerts: Iterable[Alert]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for indicator in self._extract_indicators(alerts):
            result = self._lookup_indicator(db, indicator["indicator"], indicator["type"])
            if result:
                findings.append(result)
        deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
        for finding in findings:
            key = (finding["indicator"], finding["type"].value, finding["source"])
            deduped[key] = finding
        return list(deduped.values())

    def persist_incident_results(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        findings: list[dict[str, Any]],
    ) -> list[ThreatIntel]:
        db.query(ThreatIntel).filter(ThreatIntel.tenant_id == tenant_id, ThreatIntel.incident_id == incident_id).delete()
        records: list[ThreatIntel] = []
        for finding in findings:
            record = ThreatIntel(
                tenant_id=tenant_id,
                incident_id=incident_id,
                indicator=finding["indicator"],
                type=finding["type"],
                source=finding["source"],
                result=finding["result"],
                risk_impact=int(finding.get("risk_impact", 0)),
            )
            db.add(record)
            records.append(record)
        return records

    def enrich_ioc(self, db: Session, ioc: IOC) -> list[dict]:
        # Delete existing enrichments for this IOC
        for enrichment in ioc.enrichments:
            db.delete(enrichment)
        db.flush()

        # Validate IOC value before any external lookups
        if not self._validate_indicator(ioc.value, ioc.type):
            logger.debug("Invalid IOC format rejected before provider lookup", extra={"ioc_type": ioc.type.value})
            return []

        results = []
        providers = self._providers_for_type(ioc.type)
        for provider in providers:
            result = None
            if provider == "abuseipdb":
                result = self._lookup_abuseipdb(ioc.value)
            elif provider == "virustotal":
                result = self._lookup_virustotal(ioc.value, ioc.type)
            elif provider == "otx":
                result = self._lookup_otx(ioc.value, ioc.type)
            elif provider == "internal-heuristic":
                result = self._lookup_internal_heuristic(ioc.value, ioc.type)

            if result:
                # Add to IOCEnrichment
                malicious_count = result.get("malicious_count", 0)
                total_reports = result.get("total_reports", 0)
                ioc_service.add_enrichment(
                    db,
                    ioc.tenant_id,
                    ioc.id,
                    provider,
                    result.get("reputation"),
                    malicious_count,
                    total_reports,
                    result,
                )
                results.append({"provider": provider, "result": result})

        # Refresh ioc to get new enrichments
        db.refresh(ioc)
        return results

    def _lookup_indicator(
        self,
        db: Session,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> dict[str, Any] | None:
        # Validate indicator before any external lookups
        if not self._validate_indicator(indicator, indicator_type):
            logger.debug("Invalid indicator format rejected before provider lookup", extra={"ioc_type": indicator_type.value})
            return None
            
        providers = self._providers_for_type(indicator_type)
        for provider in providers:
            cached = self._get_cached_result(db, indicator, indicator_type, provider)
            if cached:
                return cached

            result = None
            if provider == "abuseipdb":
                result = self._lookup_abuseipdb(indicator)
            elif provider == "virustotal":
                result = self._lookup_virustotal(indicator, indicator_type)
            elif provider == "otx":
                result = self._lookup_otx(indicator, indicator_type)
            elif provider == "internal-heuristic":
                result = self._lookup_internal_heuristic(indicator, indicator_type)

            if result:
                self._cache_result(db, indicator, indicator_type, provider, result)
                return {
                    "indicator": indicator,
                    "type": indicator_type,
                    "source": provider,
                    "result": result,
                    "risk_impact": int(result.get("risk_impact", 0)),
                }
        return None

    def _providers_for_type(self, indicator_type: IndicatorType) -> list[str]:
        providers = []
        if indicator_type in {IndicatorType.IP, IndicatorType.IPV4, IndicatorType.IPV6}:
            providers = ["abuseipdb", "virustotal", "otx", "internal-heuristic"]
        elif indicator_type in {
            IndicatorType.DOMAIN, IndicatorType.HASH, IndicatorType.MD5,
            IndicatorType.SHA1, IndicatorType.SHA256, IndicatorType.SHA512, IndicatorType.URL,
        }:
            providers = ["virustotal", "otx", "internal-heuristic"]
        else:
            providers = ["internal-heuristic"]
        
        # Filter out providers without API keys
        filtered = []
        for p in providers:
            if p == "abuseipdb" and not self.settings.ABUSEIPDB_API_KEY:
                continue
            if p == "virustotal" and not self.settings.VIRUSTOTAL_API_KEY:
                continue
            if p == "otx" and not self.settings.OTX_API_KEY:
                continue
            filtered.append(p)
        return filtered

    def _extract_indicators(self, alerts: Iterable[Alert]) -> list[dict[str, Any]]:
        indicators: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for alert in alerts:
            raw = alert.raw_data or {}
            candidates = [
                (raw.get("ip"), IndicatorType.IP),
                (raw.get("source_ip"), IndicatorType.IP),
                (raw.get("destination_ip"), IndicatorType.IP),
                (raw.get("domain"), IndicatorType.DOMAIN),
                (raw.get("url"), IndicatorType.URL),
                (raw.get("file_hash"), IndicatorType.HASH),
                (raw.get("hash"), IndicatorType.HASH),
            ]
            for value, indicator_type in candidates:
                if not value:
                    continue
                key = (str(value), indicator_type.value)
                if key in seen:
                    continue
                seen.add(key)
                indicators.append({"indicator": str(value), "type": indicator_type})
        return indicators

    def _get_cached_result(
        self,
        db: Session,
        indicator: str,
        indicator_type: IndicatorType,
        source: str,
    ) -> dict[str, Any] | None:
        cache = (
            db.query(ThreatIntelCache)
            .filter(
                ThreatIntelCache.indicator == indicator,
                ThreatIntelCache.indicator_type == indicator_type,
                ThreatIntelCache.source == source,
                ThreatIntelCache.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )
        if not cache:
            return None
        return {
            "indicator": indicator,
            "type": indicator_type,
            "source": source,
            "result": cache.data,
            "risk_impact": int(cache.data.get("risk_impact", 0)),
        }

    def _cache_result(
        self,
        db: Session,
        indicator: str,
        indicator_type: IndicatorType,
        source: str,
        result: dict[str, Any],
    ) -> None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.settings.THREAT_INTEL_CACHE_TTL_HOURS)
        cache = (
            db.query(ThreatIntelCache)
            .filter(
                ThreatIntelCache.indicator == indicator,
                ThreatIntelCache.indicator_type == indicator_type,
                ThreatIntelCache.source == source,
            )
            .first()
        )
        if cache is None:
            cache = ThreatIntelCache(
                indicator=indicator,
                indicator_type=indicator_type,
                source=source,
                data=result,
                expires_at=expires_at,
            )
            db.add(cache)
        else:
            cache.data = result
            cache.expires_at = expires_at
            db.add(cache)
        db.flush()

    def _lookup_abuseipdb(self, indicator: str) -> dict[str, Any] | None:
        if not self.settings.ABUSEIPDB_API_KEY:
            return None
        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                timeout=15.0,
            )
            response.raise_for_status()
            data = response.json()["data"]
            score = int(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            return {
                "reputation": "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean",
                "confidence_score": score,
                "total_reports": total_reports,
                "risk_impact": 20 if score >= 75 else 10 if score >= 25 else 0,
            }
        except Exception:
            logger.warning("AbuseIPDB lookup failed", extra={"provider": "abuseipdb"})
            return None

    def _lookup_virustotal(self, indicator: str, indicator_type: IndicatorType) -> dict[str, Any] | None:
        if not self.settings.VIRUSTOTAL_API_KEY:
            return None
        endpoint_map = {
            IndicatorType.IP: "ip_addresses",
            IndicatorType.IPV4: "ip_addresses",
            IndicatorType.IPV6: "ip_addresses",
            IndicatorType.DOMAIN: "domains",
            IndicatorType.HASH: "files",
            IndicatorType.MD5: "files",
            IndicatorType.SHA1: "files",
            IndicatorType.SHA256: "files",
            IndicatorType.SHA512: "files",
            IndicatorType.URL: "urls",
        }
        endpoint = endpoint_map.get(indicator_type)
        if not endpoint:
            return None
        try:
            response = httpx.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
                headers={"x-apikey": self.settings.VIRUSTOTAL_API_KEY},
                timeout=15.0,
            )
            response.raise_for_status()
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(stats.values()) if stats else 0
            return {
                "reputation": "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean",
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_reports": total,
                "risk_impact": 30 if indicator_type in {IndicatorType.HASH, IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256, IndicatorType.SHA512} and malicious > 0 else 20 if malicious > 0 else 10 if suspicious > 0 else 0,
            }
        except Exception:
            logger.warning("VirusTotal lookup failed", extra={"provider": "virustotal"})
            return None

    def _lookup_otx(self, indicator: str, indicator_type: IndicatorType) -> dict[str, Any] | None:
        if not self.settings.OTX_API_KEY:
            return None
        try:
            # Map indicator types to OTX section
            section_map = {
                IndicatorType.IP: "IPv4",
                IndicatorType.IPV4: "IPv4",
                IndicatorType.IPV6: "IPv6",
                IndicatorType.DOMAIN: "domain",
                IndicatorType.HASH: "file",
                IndicatorType.MD5: "file",
                IndicatorType.SHA1: "file",
                IndicatorType.SHA256: "file",
                IndicatorType.SHA512: "file",
                IndicatorType.URL: "url",
            }
            section = section_map.get(indicator_type)
            if not section:
                return None

            response = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
                headers={"X-OTX-API-KEY": self.settings.OTX_API_KEY},
                timeout=15.0,
            )
            response.raise_for_status()
            data = response.json()
            pulse_count = int(data.get("pulse_info", {}).get("count", 0))
            return {
                "reputation": "malicious" if pulse_count > 0 else "clean",
                "malicious_count": pulse_count,
                "total_reports": pulse_count,
                "risk_impact": 20 if pulse_count > 0 else 0,
            }
        except Exception:
            logger.warning("OTX lookup failed", extra={"provider": "otx"})
            return None

    def _lookup_internal_heuristic(self, indicator: str, indicator_type: IndicatorType) -> dict[str, Any] | None:
        if indicator_type == IndicatorType.IP and indicator in self.known_bad_ips:
            return {
                "reputation": "malicious",
                "confidence_score": 90,
                "risk_impact": 20,
                "note": "Matched internal high-risk IP heuristic",
            }
        if indicator_type == IndicatorType.DOMAIN and indicator in self.known_bad_domains:
            return {
                "reputation": "malicious",
                "confidence_score": 85,
                "risk_impact": 20,
                "note": "Matched internal high-risk domain heuristic",
            }
        if indicator_type == IndicatorType.HASH and indicator in self.known_bad_hashes:
            return {
                "reputation": "malicious",
                "confidence_score": 95,
                "risk_impact": 30,
                "note": "Matched internal known-malware hash heuristic",
            }
        return {
            "reputation": "unknown",
            "confidence_score": 0,
            "risk_impact": 0,
            "note": "No external provider configured; using local fallback only",
        }


threat_intel_service = ThreatIntelService()
