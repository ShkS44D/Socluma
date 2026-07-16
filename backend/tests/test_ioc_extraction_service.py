import pytest
from src.services.ioc_extraction_service import ioc_extraction_service
from src.models.sqlalchemy import IndicatorType


def test_no_ioc_for_process_names():
    """Test that common process names don't extract as IOCs"""
    test_cases = ["powershell.exe", "cmd.exe", "notepad.exe", "explorer.exe"]
    for test in test_cases:
        iocs = ioc_extraction_service.extract_from_string(test)
        assert len(iocs) == 0, f"Should not extract IOCs from {test}"


def test_extract_ip():
    """Test that valid IPs are extracted correctly"""
    test_case = "8.8.8.8"
    iocs = ioc_extraction_service.extract_from_string(test_case)
    assert len(iocs) == 1
    assert iocs[0][0] == IndicatorType.IP
    assert iocs[0][1] == "8.8.8.8"


def test_extract_url():
    """Test that valid URLs (only http/https) are extracted correctly"""
    test_case = "https://evil-example.com"
    iocs = ioc_extraction_service.extract_from_string(test_case)
    assert len(iocs) == 1
    assert iocs[0][0] == IndicatorType.URL
    assert iocs[0][1] == "https://evil-example.com"


def test_extract_domain():
    """Test that valid domains are extracted, exe files are not"""
    # Should extract domain
    domain_case = "malicious-domain.org"
    iocs_domain = ioc_extraction_service.extract_from_string(domain_case)
    assert len(iocs_domain) == 1
    assert iocs_domain[0][0] == IndicatorType.DOMAIN
    assert iocs_domain[0][1] == "malicious-domain.org"

    # Should NOT extract exe as domain
    exe_case = "malicious.exe"
    iocs_exe = ioc_extraction_service.extract_from_string(exe_case)
    assert len(iocs_exe) == 0


def test_extract_hashes():
    """Test that valid hashes are extracted"""
    md5_test = "d41d8cd98f00b204e9800998ecf8427e"
    iocs_md5 = ioc_extraction_service.extract_from_string(md5_test)
    assert len(iocs_md5) == 1
    assert iocs_md5[0][0] == IndicatorType.HASH
    assert iocs_md5[0][1] == md5_test

    sha1_test = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    iocs_sha1 = ioc_extraction_service.extract_from_string(sha1_test)
    assert len(iocs_sha1) == 1
    assert iocs_sha1[0][0] == IndicatorType.HASH
    assert iocs_sha1[0][1] == sha1_test

    sha256_test = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs_sha256 = ioc_extraction_service.extract_from_string(sha256_test)
    assert len(iocs_sha256) == 1
    assert iocs_sha256[0][0] == IndicatorType.HASH
    assert iocs_sha256[0][1] == sha256_test


def test_extract_from_dict():
    """Test IOC extraction from a dict (like alert data)"""
    test_data = {
        "ip": "192.168.1.100",
        "domain": "suspicious-site.net",
        "url": "https://phishing-site.org/login",
        "hash": "098f6bcd4621d373cade4e832627b4f6",
        "process": "powershell.exe"
    }
    iocs = ioc_extraction_service.extract_from_dict(test_data)
    # Should extract 4 IOCs (ip, domain, url, hash)
    assert len(iocs) == 4
    types = [ioc[0] for ioc in iocs]
    assert IndicatorType.IP in types
    assert IndicatorType.DOMAIN in types
    assert IndicatorType.URL in types
    assert IndicatorType.HASH in types


if __name__ == "__main__":
    pytest.main([__file__])
