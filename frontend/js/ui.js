/**
 * QR Security Engine — UI Rendering & DOM Controller
 */

export class UIController {
    static setStatusBadge(connected) {
        const badge = document.getElementById("apiStatusBadge");
        if (!badge) return;
        if (connected) {
            badge.textContent = "ENGINE ONLINE";
            badge.className = "badge status-online";
        } else {
            badge.textContent = "OFFLINE";
            badge.className = "badge status-offline";
        }
    }

    static showState(stateName) {
        const states = ["idleState", "loadingState", "resultState", "errorState"];
        states.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add("hidden");
        });

        const target = document.getElementById(`${stateName}State`);
        if (target) target.classList.remove("hidden");
    }

    static showError(message) {
        UIController.showState("error");
        const errMessage = document.getElementById("errorMessage");
        if (errMessage) errMessage.textContent = message;
    }

    static renderResult(data) {
        UIController.showState("result");

        // 1. Primary Risk Score & Badges
        const scoreVal = data.final_risk_score || 0;
        const level = data.risk_level || "LOW";
        const decision = data.decision || "ALLOW";

        document.getElementById("riskScoreText").textContent = scoreVal;
        
        const levelBadge = document.getElementById("riskLevelBadge");
        levelBadge.textContent = level;
        levelBadge.className = `badge level-${level.toLowerCase()}`;

        const decisionBadge = document.getElementById("decisionBadge");
        decisionBadge.textContent = decision;
        decisionBadge.className = `badge decision-${decision.toLowerCase()}`;

        // 2. Animated Circular SVG Risk Gauge
        UIController._updateGauge(scoreVal, level);

        // 3. Signal Breakdown (ML vs Heuristics vs Fused)
        const mlProb = data.ml_probability !== null && data.ml_probability !== undefined 
            ? `${(data.ml_probability * 100).toFixed(1)}%` 
            : "N/A";
        const heurScore = data.heuristic_score !== undefined ? `${data.heuristic_score} / 100` : "0 / 100";
        const fusedScore = `${scoreVal} / 100`;

        document.getElementById("mlProbValue").textContent = mlProb;
        document.getElementById("heurScoreValue").textContent = heurScore;
        document.getElementById("fusedScoreValue").textContent = fusedScore;

        const mlWeight = data.fusion_metadata?.ml_weight ? `(Weight: ${data.fusion_metadata.ml_weight})` : "";
        const heurWeight = data.fusion_metadata?.heuristic_weight ? `(Weight: ${data.fusion_metadata.heuristic_weight})` : "";
        document.getElementById("mlWeightText").textContent = mlWeight;
        document.getElementById("heurWeightText").textContent = heurWeight;

        // 4. Payload Metadata
        document.getElementById("payloadTypeBadge").textContent = data.payload_type || "UNKNOWN";
        const payloadText = document.getElementById("payloadText");
        payloadText.textContent = data.payload || "";

        // 5. Threat Indicators Table / List
        UIController._renderIndicators(data.indicators || []);

        // 6. Decision Timeline
        UIController._renderTimeline(data.decision_timeline || []);

        // 7. Explainability & Recommendation
        const exp = data.explanation || {};
        document.getElementById("summaryText").textContent = exp.summary || "Security analysis complete.";
        document.getElementById("recommendationText").textContent = exp.recommended_action || "Proceed with normal caution.";

        const dangerousList = document.getElementById("whyDangerousList");
        dangerousList.innerHTML = "";
        if (exp.why_dangerous && exp.why_dangerous.length > 0) {
            exp.why_dangerous.forEach(item => {
                const li = document.createElement("li");
                li.textContent = item;
                dangerousList.appendChild(li);
            });
            document.getElementById("whyDangerousContainer").classList.remove("hidden");
        } else {
            document.getElementById("whyDangerousContainer").classList.add("hidden");
        }
    }

    static _updateGauge(score, level) {
        const circle = document.getElementById("gaugeCircle");
        if (!circle) return;

        const radius = circle.r.baseVal.value;
        const circumference = 2 * Math.PI * radius;
        const strokeDashoffset = circumference - (score / 100) * circumference;

        circle.style.strokeDasharray = `${circumference} ${circumference}`;
        circle.style.strokeDashoffset = strokeDashoffset;

        const colors = {
            LOW: "#10b981",       // Emerald Green
            MEDIUM: "#f59e0b",    // Amber
            HIGH: "#ef4444",      // Red
            CRITICAL: "#8b5cf6"   // Purple
        };
        circle.style.stroke = colors[level] || colors.LOW;
    }

    static _renderIndicators(indicators) {
        const container = document.getElementById("indicatorsList");
        container.innerHTML = "";

        if (!indicators || indicators.length === 0) {
            container.innerHTML = '<div class="no-indicators">Clean payload — no threat indicators detected.</div>';
            return;
        }

        indicators.forEach(ind => {
            const card = document.createElement("div");
            card.className = `indicator-card sev-${ind.severity.toLowerCase()}`;

            const header = document.createElement("div");
            header.className = "indicator-header";

            const title = document.createElement("span");
            title.className = "indicator-title";
            title.textContent = ind.rule_id;

            const sevBadge = document.createElement("span");
            sevBadge.className = `badge level-${ind.severity.toLowerCase()}`;
            sevBadge.textContent = `${ind.severity} (+${ind.weight} pts)`;

            header.appendChild(title);
            header.appendChild(sevBadge);

            const reason = document.createElement("div");
            reason.className = "indicator-reason";
            reason.textContent = ind.reason;

            card.appendChild(header);
            card.appendChild(reason);

            if (ind.evidence) {
                const evidence = document.createElement("div");
                evidence.className = "indicator-evidence";
                evidence.textContent = `Evidence: ${ind.evidence}`;
                card.appendChild(evidence);
            }

            container.appendChild(card);
        });
    }

    static _renderTimeline(timeline) {
        const container = document.getElementById("timelineSteps");
        container.innerHTML = "";

        if (!timeline || timeline.length === 0) {
            container.innerHTML = '<div class="no-indicators">Timeline details unavailable.</div>';
            return;
        }

        timeline.forEach((step, idx) => {
            const item = document.createElement("div");
            item.className = "timeline-item";

            const stepNum = document.createElement("div");
            stepNum.className = "timeline-num";
            stepNum.textContent = idx + 1;

            const content = document.createElement("div");
            content.className = "timeline-content";

            const stageTitle = document.createElement("div");
            stageTitle.className = "timeline-stage";
            stageTitle.textContent = step.stage;

            const desc = document.createElement("div");
            desc.className = "timeline-desc";
            desc.textContent = step.description;

            content.appendChild(stageTitle);
            content.appendChild(desc);

            if (step.outcome) {
                const outcome = document.createElement("div");
                outcome.className = "timeline-outcome";
                outcome.textContent = `Outcome: ${step.outcome}`;
                content.appendChild(outcome);
            }

            item.appendChild(stepNum);
            item.appendChild(content);
            container.appendChild(item);
        });
    }
}
