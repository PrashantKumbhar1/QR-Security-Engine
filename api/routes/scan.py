import os
import uuid
import datetime
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from core.decision_engine import QRDecisionEngine
from api.dependencies import get_decision_engine
from api.schemas.scan import ScanResponseSchema, ErrorResponseSchema

router = APIRouter()

ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/bmp"}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


@router.get("/health", tags=["System"])
def health_check():
    """
    Service health check endpoint.
    """
    return {
        "status": "healthy",
        "service": "QR Security Engine API",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@router.get("/version", tags=["System"])
def version_check():
    """
    Engine version & metadata endpoint.
    """
    return {
        "version": "4.0",
        "engine": "QR Security Engine",
        "phase": "Phase 4 — Risk Fusion & FastAPI Backend"
    }


@router.post(
    "/scan",
    response_model=ScanResponseSchema,
    responses={
        400: {"model": ErrorResponseSchema, "description": "Invalid image or QR decoding failure"},
        413: {"model": ErrorResponseSchema, "description": "File size exceeds 5 MB limit"},
        415: {"model": ErrorResponseSchema, "description": "Unsupported image format"}
    },
    tags=["QR Security Analysis"]
)
async def scan_qr_code(
    file: UploadFile = File(..., description="QR code image file (PNG, JPEG, WebP, BMP)"),
    engine: QRDecisionEngine = Depends(get_decision_engine)
):
    """
    Analyzes an uploaded QR code image and returns a fused risk security assessment.
    """
    # 1. MIME Type Validation
    content_type = (file.content_type or "").lower()
    if content_type not in ALLOWED_MIME_TYPES:
        # Check filename extension if content_type is generic
        ext = os.path.splitext(file.filename or "")[1].lower()
        if ext not in {".png", ".jpg", ".jpeg", ".webp", ".bmp"}:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail={
                    "success": False,
                    "error": {
                        "code": "UNSUPPORTED_MEDIA_TYPE",
                        "message": f"File type '{content_type or ext}' is not supported. Upload a valid PNG, JPEG, WebP, or BMP image.",
                        "stage": "upload_validation"
                    }
                }
            )

    # 2. File Size Limit & Byte Reading
    try:
        contents = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "FILE_READ_ERROR",
                    "message": f"Failed to read uploaded file: {str(e)}",
                    "stage": "upload_validation"
                }
            }
        )

    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "success": False,
                "error": {
                    "code": "PAYLOAD_TOO_LARGE",
                    "message": f"File size ({len(contents)} bytes) exceeds maximum limit of 5 MB.",
                    "stage": "upload_validation"
                }
            }
        )

    # 3. Write temp image file inside workspace scratch directory
    temp_dir = os.path.join(os.getcwd(), "scratch")
    os.makedirs(temp_dir, exist_ok=True)
    scan_id = f"qr_scan_{uuid.uuid4().hex[:12]}"
    ext = os.path.splitext(file.filename or "")[1] or ".png"
    temp_path = os.path.join(temp_dir, f"{scan_id}{ext}")

    try:
        with open(temp_path, "wb") as f:
            f.write(contents)

        # 4. Execute QR Security Engine Pipeline
        analysis_result = engine.analyze_qr(temp_path)

    finally:
        # Clean up temp file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

    # 5. Format API Response
    if not analysis_result.get("success", False):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "error": {
                    "code": "QR_DECODE_FAILED",
                    "message": analysis_result.get("error", "The uploaded image does not contain a readable QR code."),
                    "stage": analysis_result.get("stage", "decoder")
                }
            }
        )

    explanation = {
        "summary": analysis_result.get("summary", ""),
        "why_dangerous": analysis_result.get("why_dangerous", []),
        "recommended_action": analysis_result.get("recommended_action", "")
    }

    return {
        "success": True,
        "scan_id": scan_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "payload": analysis_result.get("payload", ""),
        "payload_type": analysis_result.get("payload_type", "UNKNOWN"),
        "ml_probability": analysis_result.get("ml_risk_probability"),
        "heuristic_score": analysis_result.get("heuristic_score", 0),
        "final_risk_score": analysis_result.get("final_risk_score", 0),
        "risk_level": analysis_result.get("risk_level", "LOW"),
        "decision": analysis_result.get("decision", "ALLOW"),
        "fusion_metadata": analysis_result.get("fusion_metadata", {}),
        "indicators": analysis_result.get("indicators", []),
        "explanation": explanation,
        "scam_category": analysis_result.get("scam_category"),
        "decision_timeline": analysis_result.get("decision_timeline", [])
    }

