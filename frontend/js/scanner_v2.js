/**
 * QR Security Engine — File & Camera Scanner Controller (v2)
 */
import { CONFIG } from './config.js';

export class QRScannerController {
    constructor(onScanTriggered) {
        this.onScanTriggered = onScanTriggered;
        this.selectedFile = null;
        this.cameraStream = null;
        this.cameraInterval = null;

        this._initFileUpload();
        this._initCamera();
    }

    _initFileUpload() {
        const dropzone = document.getElementById("dropzone");
        const fileInput = document.getElementById("fileInput");
        const browseBtn = document.getElementById("browseBtn");

        if (!dropzone || !fileInput) return;

        browseBtn.addEventListener("click", () => fileInput.click());

        fileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                this._handleFileSelect(e.target.files[0]);
            }
        });

        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });

        dropzone.addEventListener("dragleave", () => {
            dropzone.classList.remove("dragover");
        });

        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                this._handleFileSelect(e.dataTransfer.files[0]);
            }
        });
    }

    _handleFileSelect(file) {
        const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
        if (!CONFIG.ALLOWED_EXTENSIONS.includes(ext)) {
            alert(`File type '${ext}' is not supported. Please upload a PNG, JPEG, WebP, or BMP image.`);
            return;
        }

        if (file.size > CONFIG.MAX_FILE_SIZE_BYTES) {
            alert(`File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds 5 MB limit.`);
            return;
        }

        this.selectedFile = file;
        this._showFilePreview(file);
        this.onScanTriggered(file);
    }

    _showFilePreview(file) {
        const previewContainer = document.getElementById("previewContainer");
        const previewImage = document.getElementById("previewImage");
        const previewFilename = document.getElementById("previewFilename");
        const previewFilesize = document.getElementById("previewFilesize");

        if (!previewContainer) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            previewImage.src = e.target.result;
            previewFilename.textContent = file.name;
            previewFilesize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
            previewContainer.classList.remove("hidden");
        };
        reader.readAsDataURL(file);
    }

    _initCamera() {
        const startCameraBtn = document.getElementById("startCameraBtn");
        const stopCameraBtn = document.getElementById("stopCameraBtn");
        const captureFrameBtn = document.getElementById("captureFrameBtn");
        const video = document.getElementById("cameraVideo");

        if (!startCameraBtn || !video) return;

        startCameraBtn.addEventListener("click", async () => {
            try {
                this.cameraStream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: "environment" }
                });
                video.srcObject = this.cameraStream;
                video.classList.remove("hidden");
                startCameraBtn.classList.add("hidden");
                stopCameraBtn.classList.remove("hidden");
                captureFrameBtn.classList.remove("hidden");
            } catch (err) {
                alert("Camera access failed or was denied by user: " + err.message);
            }
        });

        stopCameraBtn.addEventListener("click", () => this.stopCamera());

        captureFrameBtn.addEventListener("click", () => {
            if (!video.videoWidth) return;
            const canvas = document.createElement("canvas");
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const ctx = canvas.getContext("2d");
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

            canvas.toBlob((blob) => {
                if (blob) {
                    const cameraFile = new File([blob], "camera_capture.png", { type: "image/png" });
                    this._handleFileSelect(cameraFile);
                    this.stopCamera();
                }
            }, "image/png");
        });
    }

    stopCamera() {
        const startCameraBtn = document.getElementById("startCameraBtn");
        const stopCameraBtn = document.getElementById("stopCameraBtn");
        const captureFrameBtn = document.getElementById("captureFrameBtn");
        const video = document.getElementById("cameraVideo");

        if (this.cameraStream) {
            this.cameraStream.getTracks().forEach(track => track.stop());
            this.cameraStream = null;
        }

        if (video) {
            video.srcObject = null;
            video.classList.add("hidden");
        }

        if (startCameraBtn) startCameraBtn.classList.remove("hidden");
        if (stopCameraBtn) stopCameraBtn.classList.add("hidden");
        if (captureFrameBtn) captureFrameBtn.classList.add("hidden");
    }
}
