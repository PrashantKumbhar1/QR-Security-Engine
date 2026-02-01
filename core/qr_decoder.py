import cv2
from pyzbar.pyzbar import decode
from PIL import Image
import os


class QRDecodeError(Exception):
    """Custom exception for QR decoding failures"""
    pass


class QRDecoder:
    def __init__(self):
        pass

    def decode_qr(self, image_path: str) -> str:
        """
        Decodes a QR code from an image file.

        Args:
            image_path (str): Path to QR image

        Returns:
            str: Decoded QR payload

        Raises:
            QRDecodeError: If QR cannot be decoded
        """

        if not os.path.exists(image_path):
            raise QRDecodeError("Image file does not exist")

        try:
            image = Image.open(image_path)
            decoded_objects = decode(image)

            if not decoded_objects:
                raise QRDecodeError("No QR code detected in image")

            # Take first QR (payment apps also do this)
            qr_data = decoded_objects[0].data.decode("utf-8").strip()

            if not qr_data:
                raise QRDecodeError("QR code payload is empty")

            return qr_data

        except QRDecodeError:
            raise

        except Exception as e:
            raise QRDecodeError(f"QR decoding failed: {str(e)}")
