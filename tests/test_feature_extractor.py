import pytest
from core.feature_extractor import QRFeatureExtractor


@pytest.fixture
def extractor():
    return QRFeatureExtractor()


def test_extract_upi_features(extractor):
    data = {
        "payee_address": "user@bank",
        "payee_name": "Merchant",
        "amount": 5000.0
    }
    features = extractor.extract_upi_features(data)

    assert set(features.keys()) == set(extractor.UPI_FEATURE_KEYS)
    assert features["amount"] == 5000.0
    assert features["merchant_name_missing"] == 0
    assert features["generic_merchant_name"] == 1
    assert features["merchant_name_length"] == 8
    assert features["upi_id_length"] == 9


def test_extract_url_features(extractor):
    url = "http://bit.ly/3x897ak"
    features = extractor.extract_url_features(url)

    assert set(features.keys()) == set(extractor.URL_FEATURE_KEYS)
    assert features["has_shortener"] == 1
    assert features["is_https"] == 0
    assert features["is_ip_url"] == 0
    assert features["url_length"] == len(url)
