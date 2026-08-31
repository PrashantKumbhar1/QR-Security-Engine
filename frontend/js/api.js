/**
 * QR Security Engine — API Client
 */
import { CONFIG } from './config.js';

export class QRApiClient {
    static async checkHealth() {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}/health`);
            if (!response.ok) return false;
            const data = await response.json();
            return data.status === "healthy";
        } catch {
            return false;
        }
    }

    static async getVersion() {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}/version`);
            if (!response.ok) return null;
            return await response.json();
        } catch {
            return null;
        }
    }

    static async scanQR(fileBlob) {
        const formData = new FormData();
        formData.append("file", fileBlob);

        const response = await fetch(`${CONFIG.API_BASE_URL}/scan`, {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            const errorObj = data.error || {};
            throw new Error(errorObj.message || "QR Security Analysis failed.");
        }

        return data;
    }
}
