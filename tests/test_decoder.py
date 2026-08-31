import pytest
import os
import cv2
import numpy as np
from core.qr_decoder import QRDecoder, QRDecodeError


def test_decode_valid_qr():
    decoder = QRDecoder()
    payload = decoder.decode_qr("tests/qr_legit_url.png")
    assert payload == "https://www.example.com"



def test_decode_missing_file():
    decoder = QRDecoder()
    with pytest.raises(QRDecodeError) as exc_info:
        decoder.decode_qr("tests/non_existent_file.png")
    assert "file does not exist" in str(exc_info.value).lower()


def test_decode_non_qr_image(tmp_path):
    # Create a blank image without any QR code
    blank_img_path = str(tmp_path / "blank.png")
    blank_img = np.zeros((200, 200, 3), dtype=np.uint8)
    cv2.imwrite(blank_img_path, blank_img)

    decoder = QRDecoder()
    with pytest.raises(QRDecodeError) as exc_info:
        decoder.decode_qr(blank_img_path)
    assert "no qr code detected" in str(exc_info.value).lower()
