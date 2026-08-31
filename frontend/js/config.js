/**
 * QR Security Engine — API Configuration
 */
export const CONFIG = {
    API_BASE_URL: window.location.origin.includes("http") ? window.location.origin : "http://localhost:8000",
    MAX_FILE_SIZE_BYTES: 5 * 1024 * 1024, // 5 MB
    ALLOWED_EXTENSIONS: [".png", ".jpg", ".jpeg", ".webp", ".bmp"]
};
