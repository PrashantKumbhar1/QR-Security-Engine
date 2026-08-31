import pytest
from core.payload_classifier import QRPayloadClassifier, PayloadType


@pytest.fixture
def classifier():
    return QRPayloadClassifier()


def test_classify_upi(classifier):
    assert classifier.classify("upi://pay?pa=shop@upi&pn=Test") == PayloadType.UPI
    assert classifier.classify("  UPI://PAY?pa=test@bank  \n") == PayloadType.UPI


def test_classify_url(classifier):
    assert classifier.classify("https://example.com/login") == PayloadType.URL
    assert classifier.classify("http://192.168.1.1/admin") == PayloadType.URL
    assert classifier.classify("   https://bit.ly/3x897ak \n") == PayloadType.URL


def test_classify_text(classifier):
    assert classifier.classify("Hello QR Security Engine") == PayloadType.TEXT
    assert classifier.classify("Notice: Office opens at 9 AM") == PayloadType.TEXT


def test_classify_unknown(classifier):
    assert classifier.classify("") == PayloadType.UNKNOWN
    assert classifier.classify(None) == PayloadType.UNKNOWN
    assert classifier.classify("   \n\t  ") == PayloadType.UNKNOWN
