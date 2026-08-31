import pytest
from core.upi_parser import UPIParser, UPIParseError


@pytest.fixture
def parser():
    return UPIParser()


def test_parse_valid_upi(parser):
    payload = "upi://pay?pa=store@bank&pn=SuperStore&am=250.00&cu=INR"
    result = parser.parse(payload)
    assert result["valid"] is True
    assert result["payee_address"] == "store@bank"
    assert result["payee_name"] == "SuperStore"
    assert result["amount"] == 250.0
    assert result["currency"] == "INR"
    assert len(result["security_indicators"]) == 0


def test_parse_missing_pa(parser):
    payload = "upi://pay?pn=Store&am=100"
    with pytest.raises(UPIParseError) as exc_info:
        parser.parse(payload)
    assert "missing required upi field" in str(exc_info.value).lower()


def test_parse_missing_merchant_name(parser):
    payload = "upi://pay?pa=user@bank&am=500"
    result = parser.parse(payload)
    assert result["valid"] is True
    assert "missing_merchant_name" in result["security_indicators"]


def test_parse_embedded_url(parser):
    payload = "upi://pay?pa=scam@bank&pn=ClaimPrize&am=5000&url=http://phishing-site.com"
    result = parser.parse(payload)
    assert result["valid"] is True
    assert "embedded_external_url" in result["security_indicators"]
    assert len(result["embedded_urls"]) > 0


def test_parse_malformed_amount(parser):
    payload = "upi://pay?pa=test@upi&am=not_a_number"
    result = parser.parse(payload)
    assert result["valid"] is True
    assert "malformed_amount" in result["security_indicators"]


def test_parse_empty_payload(parser):
    with pytest.raises(UPIParseError):
        parser.parse("")
