const state = {
    currentView: "command-center",
    incidents: [],
    cachedViewData: {
        networkGraph: null,
        threatMap: null,
        hunting: null,
        compliance: null,
        sensors: null,
    },
    refreshIntervalMs: 5000,
    pollTimer: null,
    searchTerm: "",
    searchDebounceTimer: null,
    viewLoadState: {},
    chartSignatures: {
        traffic: "",
        radar: "",
        bar: "",
        threatIntelRisk: "",
        threatIntelCountry: "",
        threatIntelPorts: "",
        threatIntelVuln: "",
        huntingSeverity: "",
        huntingCertainty: "",
        huntingTopSources: "",
    },
    simulation: {
        scenarios: [],
        isLoading: false,
        activeScenarioId: "",
    },
    modal: {
        descriptionMode: "brief",
        descriptionFullText: "",
        descriptionBriefText: "",
    },
    triage: {
        pendingByIncident: {},
    },
    networkGraph: {
        instance: null,
        physicsEnabled: true,
        isInteracting: false,
        lastInteractionAt: 0,
        selectedNodeId: "",
        selectedEdgeId: "",
        persistentNodePositions: {},
        viewState: null,
        lookup: {
            nodeById: {},
            edgeById: {},
        },
    },
    threatIntel: {
        selectedRowKey: "",
        pendingFocusIp: "",
        map: {
            instance: null,
            layerGroup: null,
            viewState: null,
            hasFittedBounds: false,
            markersByIp: {},
            focusedIp: "",
        },
    },
    hunting: {
        initialized: false,
        capabilities: null,
        queryResult: null,
        lastQueryPayload: null,
        selectedScientificMethods: [],
        resultsHighlightTimer: null,
    },
};

let trafficChart = null;
let radarChart = null;
let barChart = null;
let threatIntelRiskChart = null;
let threatIntelCountryChart = null;
let threatIntelPortChart = null;
let threatIntelVulnChart = null;
let huntingSeverityChart = null;
let huntingCertaintyChart = null;
let huntingTopSourcesChart = null;

const AUTO_REFRESH_VIEWS = new Set([
    "command-center",
    "active-incidents",
    "network-graph",
    "threat-map",
    "threat-hunting",
    "compliance-logs",
    "sensor-nodes",
]);

const SEARCHABLE_VIEWS = new Set([
    "command-center",
    "active-incidents",
    "network-graph",
    "threat-map",
    "threat-hunting",
    "compliance-logs",
    "sensor-nodes",
]);

const NETWORK_GRAPH_MAX_NODES = 120;
const NETWORK_GRAPH_MAX_EDGES = 240;
const NETWORK_GRAPH_REFRESH_DEFER_MS = 2500;
const THREAT_INTEL_MAP_DEFAULT_VIEW = { lat: 18, lng: 0, zoom: 2 };
const THREAT_INTEL_MAP_MIN_FOCUS_ZOOM = 5;
const TRIAGE_STATE_OPTIONS = [
    { value: "open", label: "Open" },
    { value: "in_review", label: "In review" },
    { value: "contained", label: "Contained" },
    { value: "dismissed", label: "Dismissed" },
];
const TRIAGE_STATE_LABELS = TRIAGE_STATE_OPTIONS.reduce((acc, option) => {
    acc[option.value] = option.label;
    return acc;
}, {});
const HUNTING_DEFAULT_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const HUNTING_DEFAULT_CERTAINTY_LEVELS = ["not_sure", "probable", "certain"];
const HUNTING_DEFAULT_TRIAGE_STATES = TRIAGE_STATE_OPTIONS.map((option) => option.value);
const HUNTING_DEFAULT_SCIENTIFIC_METHODS = [
    "z_score_outliers",
    "temporal_bursts",
    "entropy_indicators",
    "clustering_lite",
];
const HUNTING_CLIENT_FALLBACK_MAX_SCAN = 1200;
const HUNTING_CLIENT_FALLBACK_MAX_LIMIT = 500;

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function severityTagClass(sev) {
    if (sev === "CRITICAL") return "tag-crit";
    if (sev === "HIGH") return "tag-warn";
    return "tag-info";
}

async function fetchJson(url, options = undefined) {
    const response = await fetch(url, options);
    if (!response.ok) {
        const body = await response.text();
        const error = new Error(`Request failed (${response.status}): ${body}`);
        error.status = response.status;
        error.responseBody = body;
        error.url = url;
        throw error;
    }
    return response.json();
}

function parseFilenameFromContentDisposition(headerValue, fallbackName) {
    const header = String(headerValue ?? "");
    if (!header) return fallbackName;
    const utfMatch = header.match(/filename\*=UTF-8''([^;]+)/i);
    if (utfMatch && utfMatch[1]) {
        try {
            return decodeURIComponent(utfMatch[1]);
        } catch {
            return fallbackName;
        }
    }
    const quotedMatch = header.match(/filename="([^"]+)"/i);
    if (quotedMatch && quotedMatch[1]) return quotedMatch[1];
    const plainMatch = header.match(/filename=([^;]+)/i);
    if (plainMatch && plainMatch[1]) return plainMatch[1].trim();
    return fallbackName;
}

async function exportIncidentsFile(format = "csv", limit = 1000) {
    const safeFormat = String(format ?? "csv").trim().toLowerCase() || "csv";
    const safeLimit = Math.max(1, Math.min(Number(limit) || 1000, 1000));
    const response = await fetch(`/api/incidents/export?format=${encodeURIComponent(safeFormat)}&limit=${safeLimit}`);
    if (!response.ok) {
        const body = await response.text();
        throw new Error(`Export failed (${response.status}): ${body}`);
    }
    const blob = await response.blob();
    const fallbackName = `sentinelai-incidents.${safeFormat}`;
    const filename = parseFilenameFromContentDisposition(response.headers.get("Content-Disposition"), fallbackName);
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
    return filename;
}

function fmtNumber(value) {
    return Number(value || 0).toLocaleString();
}

function fmtPct(value) {
    return `${Number(value || 0).toFixed(1)}%`;
}

function toSafeCount(value) {
    const raw = Number(value);
    if (!Number.isFinite(raw)) return 0;
    return Math.max(0, Math.round(raw));
}

function ratioPct(numerator, denominator) {
    const safeNumerator = Number(numerator);
    const safeDenominator = Number(denominator);
    if (!Number.isFinite(safeNumerator) || !Number.isFinite(safeDenominator) || safeDenominator <= 0) {
        return null;
    }
    return (safeNumerator / safeDenominator) * 100;
}

function fmtPctOrDash(value) {
    return Number.isFinite(Number(value)) ? fmtPct(value) : "--";
}

function confidenceRatio(value) {
    const raw = Number(value);
    if (!Number.isFinite(raw)) return null;
    const ratio = raw > 1 ? raw / 100 : raw;
    if (!Number.isFinite(ratio)) return null;
    return Math.max(0, Math.min(1, ratio));
}

function fmtConfidence(value, decimals = 1) {
    const ratio = confidenceRatio(value);
    if (ratio === null) return "--";
    return `${(ratio * 100).toFixed(decimals)}%`;
}

function normalizeTriageState(value) {
    const normalized = String(value ?? "")
        .trim()
        .toLowerCase()
        .replaceAll("-", "_")
        .replaceAll(" ", "_");
    if (TRIAGE_STATE_LABELS[normalized]) return normalized;
    return "open";
}

function triageStateLabel(value) {
    const normalized = normalizeTriageState(value);
    return TRIAGE_STATE_LABELS[normalized] || TRIAGE_STATE_LABELS.open;
}

function resolveIncidentTriage(incident) {
    const safeIncident = asObject(incident);
    const triage = asObject(safeIncident.triage);
    const stateValue = normalizeTriageState(safeIncident.triage_state ?? triage.state);
    const updatedAt = String(safeIncident.triage_updated_at ?? triage.updated_at ?? "").trim();
    return {
        state: stateValue,
        label: triageStateLabel(stateValue),
        updatedAt,
    };
}

function summarizeCounter(counterValue, emptyText, limit = 3) {
    const entries = Object.entries(asObject(counterValue))
        .map(([key, value]) => {
            const label = String(key ?? "").trim();
            const count = toSafeCount(value);
            if (!label || count <= 0) return null;
            return [label, count];
        })
        .filter((entry) => !!entry)
        .sort((a, b) => b[1] - a[1])
        .slice(0, Math.max(1, Number(limit) || 1));
    if (!entries.length) return emptyText;
    return entries.map(([label, count]) => `${label} (${fmtNumber(count)})`).join(" · ");
}

function normalizeCertaintyLevel(level) {
    const normalized = String(level ?? "").trim().toLowerCase().replaceAll(" ", "_");
    if (normalized === "certain") return "certain";
    if (normalized === "probable") return "probable";
    return "not_sure";
}

function certaintyLevelLabel(level) {
    const normalized = normalizeCertaintyLevel(level);
    if (normalized === "certain") return "Certain";
    if (normalized === "probable") return "Probable";
    return "Not sure";
}

function asObject(value) {
    return value && typeof value === "object" ? value : {};
}

function asArray(value) {
    return Array.isArray(value) ? value : [];
}

function normalizeStringList(value) {
    if (typeof value === "string") {
        const text = value.trim();
        return text ? [text] : [];
    }
    if (!Array.isArray(value)) return [];
    return value
        .map((item) => String(item ?? "").trim())
        .filter(Boolean);
}

function normalizeAlternatives(value) {
    if (!Array.isArray(value)) return [];
    return value
        .map((item) => {
            if (item && typeof item === "object") {
                const className = String(item.class ?? item.label ?? item.id ?? "").trim();
                if (!className) return null;
                const confidence = confidenceRatio(item.confidence ?? item.score);
                return { className, confidence };
            }
            if (typeof item === "string" && item.trim()) {
                return { className: item.trim(), confidence: null };
            }
            return null;
        })
        .filter((item) => !!item);
}

function resolveAttackTyping(incident) {
    const safeIncident = asObject(incident);
    const typing = safeIncident && typeof safeIncident.attack_typing === "object" ? safeIncident.attack_typing : {};
    const detail = safeIncident && typeof safeIncident.attack_detail === "object" ? safeIncident.attack_detail : {};
    const detailEvidence = detail && typeof detail.evidence === "object" ? detail.evidence : {};
    const evidence = typing && typeof typing.evidence === "object" ? typing.evidence : {};
    const detailCertainty = detail && typeof detail.certainty === "object" ? detail.certainty : {};
    const typingCertainty = typing && typeof typing.certainty === "object" ? typing.certainty : {};
    const legacyCertainty = safeIncident && typeof safeIncident.classification_certainty === "object"
        ? safeIncident.classification_certainty
        : {};
    const certainty = Object.keys(detailCertainty).length
        ? detailCertainty
        : (Object.keys(typingCertainty).length ? typingCertainty : legacyCertainty);
    const summary = String(
        detail.summary
        ?? typing.summary
        ?? typing.label
        ?? safeIncident.attack_summary
        ?? safeIncident.classification
        ?? detail.primary_class
        ?? typing.primary_class
        ?? safeIncident.classification_primary
        ?? "Unknown / Needs More Data"
    ).trim() || "Unknown / Needs More Data";
    const primaryClass = String(
        detail.primary_class
        ?? typing.primary_class
        ?? safeIncident.attack_primary_class
        ?? safeIncident.classification_primary
        ?? summary
        ?? "Unknown / Needs More Data"
    ).trim() || "Unknown / Needs More Data";
    const alternatives = normalizeAlternatives(
        Array.isArray(detail.alternatives)
            ? detail.alternatives
            : (Array.isArray(typing.alternatives) ? typing.alternatives : safeIncident.classification_alternatives)
    );
    const certaintyLevel = normalizeCertaintyLevel(certainty.level ?? safeIncident.attack_certainty_level);
    const method = String(
        detail.method
        ?? detail.source
        ?? typing.method
        ?? typing.source
        ?? safeIncident.attack_method
        ?? safeIncident.classification_source
        ?? ""
    ).trim();

    return {
        summary,
        primaryClass,
        attackConfidence: confidenceRatio(
            detail.confidence
            ?? typing.confidence
            ?? safeIncident.attack_confidence
            ?? safeIncident.classification_confidence
            ?? safeIncident.confidence
        ),
        detectionConfidence: confidenceRatio(
            safeIncident.detection_confidence ?? safeIncident.confidence
        ),
        primaryConfidence: confidenceRatio(
            detail.confidence
            ?? typing.confidence
            ?? safeIncident.attack_confidence
            ?? safeIncident.classification_confidence
            ?? safeIncident.confidence
        ),
        alternatives,
        evidenceUsed: normalizeStringList(
            Array.isArray(detailEvidence.used)
                ? detailEvidence.used
                : (Array.isArray(detail.evidence_used)
                    ? detail.evidence_used
                    : (Array.isArray(evidence.used)
                        ? evidence.used
                        : safeIncident.classification_evidence_used))
        ),
        evidenceMissing: normalizeStringList(
            Array.isArray(detailEvidence.missing)
                ? detailEvidence.missing
                : (Array.isArray(detail.evidence_missing)
                    ? detail.evidence_missing
                    : (Array.isArray(evidence.missing)
                        ? evidence.missing
                        : safeIncident.classification_evidence_missing))
        ),
        limitations: normalizeStringList(
            Array.isArray(detail.limitations)
                ? detail.limitations
                : (Array.isArray(typing.limitations) ? typing.limitations : safeIncident.classification_limitations)
        ),
        note: String(detail.note ?? typing.note ?? safeIncident.classification_note ?? "").trim(),
        rationale: normalizeStringList(
            Array.isArray(detail.rationale)
                ? detail.rationale
                : (Array.isArray(typing.rationale) ? typing.rationale : safeIncident.detection_rationale)
        ),
        source: method,
        method,
        description: String(
            detail.description ?? typing.description ?? safeIncident.attack_description ?? "No attack description available"
        ).trim() || "No attack description available",
        certaintyText: String(
            certainty.text ?? detail.certainty_text ?? ""
        ).trim(),
        certaintyLevel,
        certaintyLabel: certaintyLevelLabel(certaintyLevel),
        fieldMetadata: asObject(detail.field_metadata ?? typing.field_metadata ?? safeIncident.classification_field_metadata),
    };
}

function normalizeTypingForDisplay(value) {
    const typing = asObject(value);
    const certaintyLevel = normalizeCertaintyLevel(typing.certaintyLevel);
    const certaintyLabel = certaintyLevelLabel(certaintyLevel);
    const certaintyText = String(typing.certaintyText ?? "").trim();
    const note = String(typing.note ?? "").trim();
    const uncertaintyNote = certaintyText
        || note
        || `${certaintyLabel}: Insufficient evidence to confidently classify this incident.`;
    const evidenceMissing = normalizeStringList(typing.evidenceMissing);
    if (!evidenceMissing.length && certaintyLevel !== "certain") {
        evidenceMissing.push(
            "Additional corroborating evidence is required before this attack-family assignment can be treated as certain."
        );
    }
    const limitations = normalizeStringList(typing.limitations);
    if (!limitations.length) {
        limitations.push("Attack-family typing is deterministic and based on configured evidence rules.");
    }
    if (
        certaintyLevel !== "certain"
        && !limitations.some((item) => item.toLowerCase().includes("provisional"))
    ) {
        limitations.push("Family assignment remains provisional until missing evidence is resolved.");
    }
    const rationale = normalizeStringList(typing.rationale);
    if (!rationale.some((item) => item.toLowerCase().includes("uncertainty notes:"))) {
        rationale.push(`Uncertainty notes: ${uncertaintyNote}`);
    }
    if (
        evidenceMissing.length
        && !rationale.some((item) => {
            const normalized = item.toLowerCase();
            return normalized.includes("missing evidence") || normalized.includes("insufficient");
        })
    ) {
        rationale.push("Missing evidence currently limits deterministic certainty for this class assignment.");
    }
    return {
        ...typing,
        certaintyLevel,
        certaintyLabel,
        certaintyText,
        uncertaintyNote,
        evidenceMissing,
        limitations,
        rationale,
    };
}

function resolveAttackTypingDisplay(incident) {
    return normalizeTypingForDisplay(resolveAttackTyping(incident));
}

function normalizeAttackSnapshot(record) {
    const safeRecord = asObject(record);
    const detail = asObject(safeRecord.attack_detail);
    const certainty = asObject(safeRecord.attack_certainty);
    const detailCertainty = asObject(detail.certainty);
    const primaryClass = String(
        detail.primary_class
        ?? safeRecord.attack_primary_class
        ?? detail.summary
        ?? safeRecord.attack_summary
        ?? safeRecord.classification
        ?? "Unknown / Needs More Data"
    ).trim() || "Unknown / Needs More Data";
    return {
        primaryClass,
        attackConfidence: confidenceRatio(
            detail.confidence
            ?? safeRecord.attack_confidence_avg
            ?? safeRecord.attack_confidence
            ?? safeRecord.classification_confidence
        ),
        certaintyLevel: normalizeCertaintyLevel(
            detailCertainty.level ?? certainty.level ?? safeRecord.attack_certainty_level
        ),
    };
}

function formatAlternative(alt) {
    if (!alt) return "";
    return alt.confidence === null
        ? alt.className
        : `${alt.className} (${fmtConfidence(alt.confidence)})`;
}

function renderIncidentClassificationCell(item) {
    const safeItem = asObject(item);
    const typing = resolveAttackTypingDisplay(safeItem);
    const alternativesPreview = typing.alternatives.slice(0, 2).map(formatAlternative).join(", ");
    const extra = typing.alternatives.length > 2 ? ` +${typing.alternatives.length - 2} more` : "";
    const attackConfidence = typing.attackConfidence === null
        ? "Confidence unavailable"
        : fmtConfidence(typing.attackConfidence);
    return `
        <div class="cell-stack">
            <div>${escapeHtml(typing.summary)}</div>
            <div class="cell-meta">Primary: ${escapeHtml(typing.primaryClass)} · ${escapeHtml(attackConfidence)}</div>
            <div class="cell-meta">Uncertainty: ${escapeHtml(typing.certaintyLabel)}</div>
            <div class="cell-meta">${typing.alternatives.length
                ? `Alternatives: ${escapeHtml(alternativesPreview + extra)}`
                : "Alternatives: none reported"}</div>
        </div>
    `;
}

function renderIncidentTriageControl(item) {
    const safeItem = asObject(item);
    const incidentId = String(safeItem.id ?? "").trim();
    if (!incidentId) return "--";
    const triage = resolveIncidentTriage(safeItem);
    const pending = !!state.triage.pendingByIncident[incidentId];
    const optionsMarkup = TRIAGE_STATE_OPTIONS.map((option) => `
        <option value="${escapeHtml(option.value)}"${option.value === triage.state ? " selected" : ""}>${escapeHtml(option.label)}</option>
    `).join("");
    const updatedMeta = triage.updatedAt
        ? `Updated: ${new Date(triage.updatedAt).toLocaleString()}`
        : "Not updated";
    return `
        <div class="incident-triage-controls">
            <select class="incident-triage-select" data-incident-id="${escapeHtml(incidentId)}" ${pending ? "disabled" : ""} aria-label="Triage state for ${escapeHtml(incidentId)}" title="${escapeHtml(updatedMeta)}">
                ${optionsMarkup}
            </select>
        </div>
    `;
}

function applyIncidentTriageUpdate(incidentId, triageState, triageUpdatedAt = "") {
    const normalizedIncidentId = String(incidentId ?? "").trim();
    if (!normalizedIncidentId) return;
    const normalizedState = normalizeTriageState(triageState);
    const normalizedUpdatedAt = String(triageUpdatedAt ?? "").trim();
    state.incidents = state.incidents.map((incident) => {
        if (String(incident.id ?? "").trim() !== normalizedIncidentId) return incident;
        return {
            ...incident,
            triage_state: normalizedState,
            triage_updated_at: normalizedUpdatedAt || null,
            triage: {
                ...asObject(incident.triage),
                state: normalizedState,
                updated_at: normalizedUpdatedAt || null,
            },
        };
    });
}

function renderListItems(items, emptyText) {
    const values = normalizeStringList(items);
    if (!values.length) {
        return `<li class="list-empty">${escapeHtml(emptyText)}</li>`;
    }
    return values.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function shortText(value, maxLen = 110) {
    const text = String(value ?? "");
    if (text.length <= maxLen) return text;
    return `${text.slice(0, maxLen - 1)}...`;
}

function setModalDescriptionMode(mode = "brief") {
    const normalizedMode = String(mode ?? "").toLowerCase() === "full" ? "full" : "brief";
    state.modal.descriptionMode = normalizedMode;
    const text = normalizedMode === "full"
        ? state.modal.descriptionFullText
        : state.modal.descriptionBriefText;
    const descriptionEl = document.getElementById("modDescription");
    if (descriptionEl) {
        descriptionEl.textContent = text || "No description available";
    }
    const toggleEl = document.getElementById("modDescriptionToggle");
    if (!toggleEl) return;
    toggleEl.querySelectorAll(".description-toggle-btn").forEach((button) => {
        const isActive = button.dataset.descriptionMode === normalizedMode;
        button.classList.toggle("active", isActive);
        button.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
}

function normalizeSimulationScenario(value) {
    const item = asObject(value);
    const id = String(item.id ?? "").trim();
    if (!id) return null;
    const defaults = asObject(item.defaults);
    return {
        id,
        name: String(item.name ?? id).trim() || id,
        description: String(item.description ?? "").trim(),
        attackFamilyHint: String(item.attack_family_hint ?? "").trim(),
        triggerCount: Math.max(1, Number(defaults.trigger_count) || 1),
    };
}

function setSimulationTriggerLoading(loading, scenarioId = "") {
    state.simulation.isLoading = !!loading;
    state.simulation.activeScenarioId = loading ? String(scenarioId ?? "").trim() : "";
    const buttons = document.querySelectorAll("#simulationScenarioButtons .simulation-trigger-btn");
    buttons.forEach((button) => {
        const isActive = state.simulation.isLoading && button.dataset.scenarioId === state.simulation.activeScenarioId;
        button.disabled = state.simulation.isLoading;
        button.classList.toggle("is-loading", isActive);
        const labelEl = button.querySelector(".simulation-trigger-name");
        if (labelEl) {
            labelEl.textContent = isActive ? "Triggering..." : (button.dataset.defaultLabel || "Trigger");
        }
    });
}

function renderSimulationScenarioButtons() {
    const container = document.getElementById("simulationScenarioButtons");
    if (!container) return;
    const scenarios = asArray(state.simulation.scenarios);
    if (!scenarios.length) {
        container.innerHTML = `<div class="simulation-empty">No simulation scenarios available</div>`;
        return;
    }
    container.innerHTML = scenarios.map((scenario) => {
        const details = [scenario.attackFamilyHint, scenario.description].filter(Boolean).join(" · ");
        return `
            <button class="btn simulation-trigger-btn" type="button" data-scenario-id="${escapeHtml(scenario.id)}">
                <span class="simulation-trigger-name">${escapeHtml(scenario.name)}</span>
                <span class="simulation-trigger-meta">${escapeHtml(details || "Trigger simulation scenario")}</span>
            </button>
        `;
    }).join("");
    container.querySelectorAll(".simulation-trigger-btn").forEach((button) => {
        const labelEl = button.querySelector(".simulation-trigger-name");
        button.dataset.defaultLabel = labelEl ? labelEl.textContent || "Trigger" : "Trigger";
    });
    setSimulationTriggerLoading(state.simulation.isLoading, state.simulation.activeScenarioId);
}

async function triggerSimulationScenario(scenarioId, count = 1) {
    const payload = await fetchJson("/api/simulation/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            scenario_id: scenarioId,
            count,
        }),
    });
    return asObject(payload);
}

async function saveIncidentTriageState(incidentId, triageState) {
    const payload = await fetchJson(`/api/incidents/${encodeURIComponent(incidentId)}/triage`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            state: triageState,
        }),
    });
    return asObject(payload);
}

const VIEW_LABELS = {
    "command-center": "Command Center",
    "network-graph": "Network Graph",
    "threat-map": "Threat Intel",
    "active-incidents": "Active Incidents",
    "threat-hunting": "Threat Hunting",
    "compliance-logs": "Compliance Logs",
    "detection-rules": "Detection Rules",
    "sensor-nodes": "Sensor Nodes",
    settings: "Settings",
};

function networkGraphEdgeId(source, target) {
    return `${String(source ?? "")}=>${String(target ?? "")}`;
}

function markNetworkGraphInteraction(active = false) {
    state.networkGraph.isInteracting = !!active;
    state.networkGraph.lastInteractionAt = Date.now();
}

function shouldDeferNetworkGraphRefresh() {
    if (state.currentView !== "network-graph") return false;
    if (state.networkGraph.isInteracting) return true;
    const lastAt = Number(state.networkGraph.lastInteractionAt || 0);
    if (!Number.isFinite(lastAt) || lastAt <= 0) return false;
    return (Date.now() - lastAt) < NETWORK_GRAPH_REFRESH_DEFER_MS;
}

function snapshotNetworkGraphViewState() {
    const network = state.networkGraph.instance;
    if (!network) return;
    const viewPosition = network.getViewPosition();
    const scale = network.getScale();
    const isValidPosition = viewPosition
        && Number.isFinite(Number(viewPosition.x))
        && Number.isFinite(Number(viewPosition.y));
    if (!isValidPosition || !Number.isFinite(Number(scale))) return;
    state.networkGraph.viewState = {
        position: { x: Number(viewPosition.x), y: Number(viewPosition.y) },
        scale: Number(scale),
    };
}

function snapshotNetworkGraphNodePositions() {
    const network = state.networkGraph.instance;
    if (!network) return;
    const positions = asObject(network.getPositions());
    const next = {};
    Object.entries(positions).forEach(([id, value]) => {
        const point = asObject(value);
        const x = Number(point.x);
        const y = Number(point.y);
        if (!Number.isFinite(x) || !Number.isFinite(y)) return;
        next[String(id)] = { x, y };
    });
    state.networkGraph.persistentNodePositions = next;
}

function snapshotNetworkGraphState() {
    snapshotNetworkGraphNodePositions();
    snapshotNetworkGraphViewState();
}

function restoreNetworkGraphViewState() {
    const network = state.networkGraph.instance;
    if (!network) return;
    const saved = asObject(state.networkGraph.viewState);
    const position = asObject(saved.position);
    const x = Number(position.x);
    const y = Number(position.y);
    const scale = Number(saved.scale);
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(scale)) return;
    network.moveTo({
        position: { x, y },
        scale,
        animation: false,
    });
}

function setNetworkGraphStatus(message = "", variant = "") {
    setStatusMessage("networkGraphStatus", message, variant);
}

function setNetworkGraphSelectionText(message = "") {
    const target = document.getElementById("networkGraphSelection");
    if (!target) return;
    target.textContent = message || "Select a node or edge to inspect relationship details.";
}

function isViewSearchable(view = state.currentView) {
    return SEARCHABLE_VIEWS.has(view);
}

function isViewAutoRefreshEnabled(view = state.currentView) {
    return AUTO_REFRESH_VIEWS.has(view);
}

function getSearchTerm() {
    return String(state.searchTerm ?? "").trim().toLowerCase();
}

function flattenSearchableValue(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        return String(value).toLowerCase();
    }
    if (Array.isArray(value)) {
        return value.map((item) => flattenSearchableValue(item)).join(" ");
    }
    if (typeof value === "object") {
        return Object.values(value).map((item) => flattenSearchableValue(item)).join(" ");
    }
    return "";
}

function matchesSearch(item, searchTerm = getSearchTerm()) {
    if (!searchTerm) return true;
    return flattenSearchableValue(item).includes(searchTerm);
}

function filterBySearch(items, searchTerm = getSearchTerm()) {
    const safeItems = asArray(items).filter((item) => item && typeof item === "object");
    if (!searchTerm) return safeItems;
    return safeItems.filter((item) => matchesSearch(item, searchTerm));
}

function buildEmptyStateMessage(defaultMessage, searchTerm = getSearchTerm()) {
    if (!searchTerm) return defaultMessage;
    return `No results for "${state.searchTerm.trim()}". Clear search to view all data.`;
}

function getViewElement(view = state.currentView) {
    return document.querySelector(`.view[data-view="${view}"]`);
}

function ensureViewMetaIndicators(view) {
    const section = getViewElement(view);
    if (!section) return null;
    const header = section.querySelector(".page-header");
    if (!header) return null;
    let indicators = header.querySelector(".view-meta-indicators");
    if (!indicators) {
        indicators = document.createElement("div");
        indicators.className = "view-meta-indicators";
        header.appendChild(indicators);
    }
    return indicators;
}

function setViewMetaIndicators(view, entries) {
    const indicators = ensureViewMetaIndicators(view);
    if (!indicators) return;
    const normalized = asArray(entries)
        .map((entry) => {
            const safeEntry = asObject(entry);
            const meta = asObject(safeEntry.meta);
            if (!Object.keys(meta).length) return null;
            const label = String(safeEntry.label ?? "Data").trim() || "Data";
            const source = String(meta.source ?? "unknown").trim() || "unknown";
            const staged = !!meta.staged;
            return `${label}|${source}|${staged ? "staged" : "live"}`;
        })
        .filter(Boolean);
    const unique = Array.from(new Set(normalized));
    if (!unique.length) {
        indicators.innerHTML = "";
        return;
    }
    indicators.innerHTML = unique.map((token) => {
        const [label, source, mode] = token.split("|");
        const staged = mode === "staged";
        return `<span class="tag ${staged ? "tag-warn" : "tag-info"}">${escapeHtml(label)}: ${staged ? "STAGED" : "LIVE"} · ${escapeHtml(source)}</span>`;
    }).join("");
}

function ensureViewFeedback(view) {
    const section = getViewElement(view);
    if (!section) return null;
    let feedback = section.querySelector(".view-feedback");
    if (!feedback) {
        feedback = document.createElement("div");
        feedback.className = "view-feedback";
        feedback.innerHTML = `
            <div class="view-feedback-message"></div>
            <button class="btn" type="button">Retry</button>
        `;
        const header = section.querySelector(".page-header");
        if (header) {
            header.insertAdjacentElement("afterend", feedback);
        } else {
            section.prepend(feedback);
        }
        const retryBtn = feedback.querySelector("button");
        retryBtn.addEventListener("click", () => {
            if (state.currentView !== view) {
                setView(view);
                return;
            }
            loadCurrentView();
        });
    }
    return feedback;
}

function clearViewFeedback(view) {
    const feedback = ensureViewFeedback(view);
    if (!feedback) return;
    feedback.classList.remove("active", "stale");
    const messageEl = feedback.querySelector(".view-feedback-message");
    if (messageEl) messageEl.textContent = "";
}

function showViewError(view, error, hasStaleData = false) {
    const feedback = ensureViewFeedback(view);
    if (!feedback) return;
    const label = VIEW_LABELS[view] ?? "view";
    const detail = String(error?.message ?? "Unknown error").trim();
    const message = hasStaleData
        ? `Failed to refresh ${label}. Showing previously loaded data. ${detail}`
        : `Failed to load ${label}. ${detail}`;
    const messageEl = feedback.querySelector(".view-feedback-message");
    if (messageEl) messageEl.textContent = message;
    feedback.classList.add("active");
    feedback.classList.toggle("stale", hasStaleData);
}

function markViewLoaded(view) {
    state.viewLoadState[view] = {
        ...(asObject(state.viewLoadState[view])),
        hasData: true,
        loadedAt: Date.now(),
    };
    clearViewFeedback(view);
}

function setStatusMessage(id, message, variant = "") {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = message;
    el.classList.remove("is-success", "is-error", "is-pending");
    if (variant) {
        el.classList.add(`is-${variant}`);
    }
}

function setInputInvalidState(inputIds, invalidIds = new Set()) {
    asArray(inputIds).forEach((id) => {
        const el = document.getElementById(String(id));
        if (!el) return;
        el.classList.toggle("is-invalid", invalidIds.has(String(id)));
    });
}

function readNumericField({ id, label, min = null, max = null, integer = false }) {
    const input = document.getElementById(id);
    const raw = String(input?.value ?? "").trim();
    if (!raw) {
        return { ok: false, id, message: `${label} is required.` };
    }
    const value = Number(raw);
    if (!Number.isFinite(value)) {
        return { ok: false, id, message: `${label} must be a valid number.` };
    }
    if (integer && !Number.isInteger(value)) {
        return { ok: false, id, message: `${label} must be an integer.` };
    }
    if (min !== null && value < min) {
        return { ok: false, id, message: `${label} must be >= ${min}.` };
    }
    if (max !== null && value > max) {
        return { ok: false, id, message: `${label} must be <= ${max}.` };
    }
    return { ok: true, value };
}

function validateRulesForm() {
    const fields = [
        { id: "ruleThreshold", label: "Alert threshold", min: 0, max: 1 },
        { id: "ruleLoopWindow", label: "Loopback window seconds", min: 1, integer: true },
        { id: "ruleLoopPorts", label: "Loopback min distinct ports for scan", min: 1, integer: true },
        { id: "ruleAttackMinScore", label: "Attack typing minimum score", min: 0 },
        { id: "ruleAttackMinMargin", label: "Attack typing minimum margin", min: 0 },
        { id: "ruleAttackMaxAlternatives", label: "Attack typing max alternatives", min: 1, integer: true },
    ];

    const invalidIds = new Set();
    const values = {};
    for (const field of fields) {
        const parsed = readNumericField(field);
        if (!parsed.ok) {
            invalidIds.add(field.id);
            setInputInvalidState(fields.map((item) => item.id).concat(["ruleAttackFallbackClass"]), invalidIds);
            return { ok: false, message: parsed.message };
        }
        values[field.id] = parsed.value;
    }

    const fallbackClass = String(document.getElementById("ruleAttackFallbackClass")?.value ?? "").trim();
    if (!fallbackClass) {
        invalidIds.add("ruleAttackFallbackClass");
        setInputInvalidState(fields.map((item) => item.id).concat(["ruleAttackFallbackClass"]), invalidIds);
        return { ok: false, message: "Attack typing fallback class id must be non-empty." };
    }

    setInputInvalidState(fields.map((item) => item.id).concat(["ruleAttackFallbackClass"]), new Set());
    return {
        ok: true,
        body: {
            alert_threshold: values.ruleThreshold,
            loopback_window_seconds: values.ruleLoopWindow,
            loopback_min_distinct_ports_for_scan: values.ruleLoopPorts,
            attack_typing: {
                minimum_score: values.ruleAttackMinScore,
                minimum_margin: values.ruleAttackMinMargin,
                fallback_class_id: fallbackClass,
                max_alternatives: values.ruleAttackMaxAlternatives,
            },
        },
    };
}

function validateSettingsForm() {
    const parsed = readNumericField({
        id: "settingRefresh",
        label: "Refresh interval seconds",
        min: 1,
        integer: true,
    });
    if (!parsed.ok) {
        setInputInvalidState(["settingRefresh"], new Set(["settingRefresh"]));
        return { ok: false, message: parsed.message };
    }
    setInputInvalidState(["settingRefresh"], new Set());
    return {
        ok: true,
        body: {
            refresh_interval_seconds: parsed.value,
            enable_staged_data: !!document.getElementById("settingStaged")?.checked,
        },
    };
}

function setButtonLoadingState(buttonId, loading, loadingText) {
    const button = document.getElementById(buttonId);
    if (!button) return;
    if (loading) {
        if (!button.dataset.originalText) {
            button.dataset.originalText = button.textContent || "";
        }
        button.disabled = true;
        button.classList.add("is-loading");
        if (loadingText) {
            button.textContent = loadingText;
        }
        return;
    }
    button.disabled = false;
    button.classList.remove("is-loading");
    if (button.dataset.originalText) {
        button.textContent = button.dataset.originalText;
    }
}

function debounceViewReload(delayMs = 180) {
    if (state.searchDebounceTimer) {
        clearTimeout(state.searchDebounceTimer);
    }
    state.searchDebounceTimer = setTimeout(() => {
        if (!isViewSearchable(state.currentView)) {
            return;
        }
        if (!rerenderCurrentViewForSearch()) {
            loadCurrentView();
        }
    }, delayMs);
}

function chartSignature(data) {
    return JSON.stringify(data ?? {});
}

function updateClock() {
    const now = new Date();
    document.getElementById("sysClock").textContent = `${now.toISOString().substring(11, 19)} UTC`;
}

function attachNavigation() {
    const navButtons = document.querySelectorAll(".nav-item");
    navButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const view = btn.dataset.view;
            if (!view) return;
            setView(view);
        });
    });
}

function setView(view) {
    state.currentView = view;
    document.querySelectorAll(".nav-item").forEach((el) => {
        el.classList.toggle("active", el.dataset.view === view);
    });
    document.querySelectorAll(".view").forEach((el) => {
        el.classList.toggle("active", el.dataset.view === view);
    });
    window.location.hash = view;
    loadCurrentView();
}

function requestThreatIntelFocus(ip, { openView = false, applySearch = false } = {}) {
    const normalizedIp = String(ip ?? "").trim();
    if (!normalizedIp || normalizedIp === "--") return;
    state.threatIntel.pendingFocusIp = normalizedIp;
    setThreatIntelMapStatus(`Locating ${normalizedIp} on threat map...`, "pending");
    if (applySearch) {
        state.searchTerm = normalizedIp;
        const searchInput = document.getElementById("globalSearch");
        if (searchInput) {
            searchInput.value = normalizedIp;
        }
    }
    if (openView) {
        setView("threat-map");
        return;
    }
    if (state.currentView === "threat-map" && state.cachedViewData.threatMap) {
        renderThreatMapTable(state.cachedViewData.threatMap);
        renderThreatIntelMap(state.cachedViewData.threatMap);
    }
}

function renderIncidentRows(targetId, items, options = {}) {
    const tbody = document.getElementById(targetId);
    if (!tbody) return;
    const isActiveTable = targetId === "activeIncidentsRows";
    const emptyColspan = isActiveTable ? 8 : 6;
    const safeOptions = asObject(options);
    const safeItems = asArray(items).filter((item) => item && typeof item === "object");
    if (!safeItems.length) {
        const emptyMessage = String(safeOptions.emptyMessage ?? "No incidents");
        tbody.innerHTML = `<tr><td colspan="${emptyColspan}">${escapeHtml(emptyMessage)}</td></tr>`;
        return;
    }
    tbody.innerHTML = safeItems.map((item) => {
        const typing = resolveAttackTypingDisplay(item);
        const incidentId = String(item.id ?? "--");
        const timestamp = item.timestamp ? String(item.timestamp).slice(0, 19).replace("T", " ") : "--";
        const source = isActiveTable ? (item.attacker_ip || item.source_ip || "--") : (item.source_ip || item.attacker_ip || "--");
        const sourceCell = isActiveTable
            ? `<button type="button" class="table-link-btn incident-map-jump" data-ip="${escapeHtml(source)}">${escapeHtml(source)}</button>`
            : escapeHtml(source);
        const severity = String(item.severity || "LOW");
        const confidenceForDisplay = typing.attackConfidence ?? typing.detectionConfidence;
        const triageControl = isActiveTable ? renderIncidentTriageControl(item) : "";
        return `
        <tr class="interactive incident-row" data-incident-id="${escapeHtml(incidentId)}">
            <td class="mono">${escapeHtml(incidentId)}</td>
            <td class="mono">${escapeHtml(timestamp)}</td>
            <td class="mono">${sourceCell}</td>
            ${isActiveTable
        ? `<td class="mono">${escapeHtml(item.target_ip || "--")}</td><td>${renderIncidentClassificationCell(item)}</td>`
        : `<td>${renderIncidentClassificationCell(item)}</td><td>${escapeHtml(shortText(typing.description || "No attack description available"))}</td>`}
            <td><span class="tag ${severityTagClass(severity)}">${escapeHtml(severity)}</span></td>
            ${isActiveTable ? `<td>${escapeHtml(fmtConfidence(confidenceForDisplay, 2))}</td><td>${triageControl}</td>` : ""}
        </tr>
    `;
    }).join("");

    tbody.querySelectorAll(".incident-row").forEach((row) => {
        row.addEventListener("click", () => {
            const found = state.incidents.find((inc) => inc.id === row.dataset.incidentId);
            if (found) openIncidentModal(found);
        });
    });
    if (!isActiveTable) return;
    tbody.querySelectorAll(".incident-map-jump").forEach((button) => {
        ["click", "mousedown", "keydown"].forEach((eventName) => {
            button.addEventListener(eventName, (event) => {
                event.stopPropagation();
            });
        });
        button.addEventListener("click", () => {
            const ip = String(button.dataset.ip ?? "").trim();
            requestThreatIntelFocus(ip, { openView: true, applySearch: false });
        });
    });
    tbody.querySelectorAll(".incident-triage-select").forEach((selectEl) => {
        ["click", "mousedown", "keydown"].forEach((eventName) => {
            selectEl.addEventListener(eventName, (event) => {
                event.stopPropagation();
            });
        });
        selectEl.addEventListener("change", async (event) => {
            event.stopPropagation();
            const target = event.currentTarget;
            const incidentId = String(target?.dataset?.incidentId ?? "").trim();
            if (!incidentId) return;
            const selectedState = normalizeTriageState(target.value);
            const currentIncident = state.incidents.find((incident) => String(incident.id ?? "").trim() === incidentId);
            const previousTriage = resolveIncidentTriage(currentIncident);
            if (selectedState === previousTriage.state) return;

            state.triage.pendingByIncident[incidentId] = true;
            applyIncidentTriageUpdate(incidentId, selectedState, previousTriage.updatedAt);
            renderActiveIncidentTable();
            setStatusMessage(
                "incidentTriageStatus",
                `Updating ${incidentId} triage to ${triageStateLabel(selectedState)}...`,
                "pending"
            );

            try {
                const payload = await saveIncidentTriageState(incidentId, selectedState);
                const triagePayload = asObject(payload.triage);
                const savedState = normalizeTriageState(triagePayload.state ?? selectedState);
                const savedUpdatedAt = String(triagePayload.updated_at ?? new Date().toISOString()).trim();
                applyIncidentTriageUpdate(incidentId, savedState, savedUpdatedAt);
                setStatusMessage(
                    "incidentTriageStatus",
                    `${incidentId} triage set to ${triageStateLabel(savedState)}.`,
                    "success"
                );
            } catch (error) {
                applyIncidentTriageUpdate(incidentId, previousTriage.state, previousTriage.updatedAt);
                setStatusMessage(
                    "incidentTriageStatus",
                    String(error?.message ?? "Failed to update incident triage state"),
                    "error"
                );
            } finally {
                delete state.triage.pendingByIncident[incidentId];
                renderActiveIncidentTable();
            }
        });
    });
}

function renderCommandCenterIncidentTable() {
    const searchTerm = getSearchTerm();
    const filteredIncidents = filterBySearch(state.incidents, searchTerm);
    renderIncidentRows("incidentRows", filteredIncidents.slice(0, 20), {
        emptyMessage: buildEmptyStateMessage("No incidents", searchTerm),
    });
}

function renderAttackObservabilityWidget(metaPayload) {
    const subtitleEl = document.getElementById("attackObsSubtitle");
    const fallbackRateEl = document.getElementById("attackObsFallbackRate");
    const fallbackCountEl = document.getElementById("attackObsFallbackCount");
    const lowConfidenceRateEl = document.getElementById("attackObsLowConfidenceRate");
    const lowConfidenceCountEl = document.getElementById("attackObsLowConfidenceCount");
    const gateFailureRateEl = document.getElementById("attackObsGateFailureRate");
    const gateFailureCountEl = document.getElementById("attackObsGateFailureCount");
    const ruleHitRateEl = document.getElementById("attackObsRuleHitRate");
    const ruleHitCountEl = document.getElementById("attackObsRuleHitCount");
    const gatePassRateEl = document.getElementById("attackObsGatePassRate");
    const gatePassCountEl = document.getElementById("attackObsGatePassCount");
    const fallbackFieldsEl = document.getElementById("attackObsFallbackFields");
    const lowConfidenceFieldsEl = document.getElementById("attackObsLowConfidenceFields");
    const gateBreakdownEl = document.getElementById("attackObsGateFailureBreakdown");
    if (
        !subtitleEl
        || !fallbackRateEl
        || !fallbackCountEl
        || !lowConfidenceRateEl
        || !lowConfidenceCountEl
        || !gateFailureRateEl
        || !gateFailureCountEl
        || !ruleHitRateEl
        || !ruleHitCountEl
        || !gatePassRateEl
        || !gatePassCountEl
        || !fallbackFieldsEl
        || !lowConfidenceFieldsEl
        || !gateBreakdownEl
    ) {
        return;
    }

    const meta = asObject(metaPayload);
    const observability = asObject(meta.attack_detail_observability);
    const ruleCoverage = asObject(observability.rule_hit_coverage);
    const gateFailures = asObject(observability.gate_failure_distribution);

    const incidentCount = toSafeCount(observability.incident_count);
    const fallbackCount = toSafeCount(observability.incidents_with_fallback_fields);
    const lowConfidenceCount = toSafeCount(observability.incidents_with_low_confidence_fields);

    const scoredIncidentCount = toSafeCount(
        ruleCoverage.scored_incident_count ?? gateFailures.scored_incident_count
    );
    const ruleHitCount = toSafeCount(ruleCoverage.incidents_with_rule_hits);
    const gatePassCount = toSafeCount(ruleCoverage.incidents_with_gates_passed);
    const gateFailureCount = toSafeCount(gateFailures.incidents_with_any_gate_failure);

    const fallbackRate = ratioPct(fallbackCount, incidentCount);
    const lowConfidenceRate = ratioPct(lowConfidenceCount, incidentCount);
    const gateFailureRate = ratioPct(gateFailureCount, scoredIncidentCount);
    const ruleHitRate = scoredIncidentCount
        ? Number(ruleCoverage.rule_hit_rate_pct ?? ratioPct(ruleHitCount, scoredIncidentCount))
        : null;
    const gatePassRate = scoredIncidentCount
        ? Number(ruleCoverage.gate_pass_rate_pct ?? ratioPct(gatePassCount, scoredIncidentCount))
        : null;

    const lowConfidenceThreshold = Number(observability.low_confidence_threshold);
    const lowConfidenceThresholdText = Number.isFinite(lowConfidenceThreshold)
        ? lowConfidenceThreshold.toFixed(2)
        : "--";
    subtitleEl.textContent = `Coverage: ${fmtNumber(incidentCount)} incidents (${fmtNumber(scoredIncidentCount)} scored) · low-confidence threshold < ${lowConfidenceThresholdText}`;

    fallbackRateEl.textContent = fmtPctOrDash(fallbackRate);
    fallbackCountEl.textContent = `${fmtNumber(fallbackCount)} / ${fmtNumber(incidentCount)} incidents`;

    lowConfidenceRateEl.textContent = fmtPctOrDash(lowConfidenceRate);
    lowConfidenceCountEl.textContent = `${fmtNumber(lowConfidenceCount)} / ${fmtNumber(incidentCount)} incidents`;

    gateFailureRateEl.textContent = fmtPctOrDash(gateFailureRate);
    gateFailureCountEl.textContent = `${fmtNumber(gateFailureCount)} / ${fmtNumber(scoredIncidentCount)} scored`;

    ruleHitRateEl.textContent = fmtPctOrDash(ruleHitRate);
    ruleHitCountEl.textContent = `${fmtNumber(ruleHitCount)} / ${fmtNumber(scoredIncidentCount)} scored`;

    gatePassRateEl.textContent = fmtPctOrDash(gatePassRate);
    gatePassCountEl.textContent = `${fmtNumber(gatePassCount)} / ${fmtNumber(scoredIncidentCount)} scored`;

    fallbackFieldsEl.textContent = summarizeCounter(
        observability.fallback_field_usage,
        "No fallback fields observed"
    );
    lowConfidenceFieldsEl.textContent = summarizeCounter(
        observability.low_confidence_field_usage,
        "No low-confidence fields observed"
    );
    gateBreakdownEl.textContent = summarizeCounter(
        {
            score: gateFailures.score_gate_failures,
            margin: gateFailures.margin_gate_failures,
            evidence_missing: gateFailures.required_evidence_missing_failures,
            ambiguity: gateFailures.ambiguity_failures,
        },
        "No gate failures observed",
        4
    );
}

function renderActiveIncidentTable() {
    const searchTerm = getSearchTerm();
    const filteredIncidents = filterBySearch(state.incidents, searchTerm);
    renderIncidentRows("activeIncidentsRows", filteredIncidents, {
        emptyMessage: buildEmptyStateMessage("No incidents", searchTerm),
    });
}

function prepareNetworkGraphData(payload) {
    const safePayload = asObject(payload);
    const searchTerm = getSearchTerm();
    const availableNodes = asArray(safePayload.nodes).filter((item) => item && typeof item === "object");
    const availableEdges = asArray(safePayload.edges).filter((item) => item && typeof item === "object");

    let allNodes = filterBySearch(availableNodes, searchTerm);
    let allEdges = filterBySearch(availableEdges, searchTerm);
    let searchFallbackApplied = false;
    if (searchTerm && !allNodes.length && availableNodes.length) {
        allNodes = availableNodes;
        allEdges = availableEdges;
        searchFallbackApplied = true;
    }

    const sortedNodes = [...allNodes].sort(
        (a, b) => Number(b.incident_count ?? 0) - Number(a.incident_count ?? 0)
    );
    const nodes = sortedNodes.slice(0, NETWORK_GRAPH_MAX_NODES);
    const nodeIds = new Set(nodes.map((node) => String(node.id ?? "").trim()).filter(Boolean));

    const sortedEdges = [...allEdges]
        .filter((edge) => {
            const source = String(edge.source ?? "").trim();
            const target = String(edge.target ?? "").trim();
            return source && target && nodeIds.has(source) && nodeIds.has(target);
        })
        .sort((a, b) => Number(b.weight ?? 0) - Number(a.weight ?? 0));
    const edges = sortedEdges.slice(0, NETWORK_GRAPH_MAX_EDGES);

    return {
        searchTerm,
        nodes,
        edges,
        searchFallbackApplied,
        truncatedNodes: allNodes.length > nodes.length,
        truncatedEdges: sortedEdges.length > edges.length,
        totalNodeMatches: allNodes.length,
        totalEdgeMatches: sortedEdges.length,
        totalNodeAvailable: availableNodes.length,
        totalEdgeAvailable: availableEdges.length,
    };
}

function syncNetworkGraphTableSelection() {
    const nodeId = String(state.networkGraph.selectedNodeId ?? "");
    const edgeId = String(state.networkGraph.selectedEdgeId ?? "");
    document.querySelectorAll("#networkNodesRows tr.network-node-row").forEach((row) => {
        row.classList.toggle("is-selected", !!nodeId && row.dataset.nodeId === nodeId);
    });
    document.querySelectorAll("#networkEdgesRows tr.network-edge-row").forEach((row) => {
        const matchesEdge = !!edgeId && row.dataset.edgeId === edgeId;
        const matchesNode = !!nodeId && (row.dataset.source === nodeId || row.dataset.target === nodeId);
        row.classList.toggle("is-selected", matchesEdge || (!edgeId && matchesNode));
    });
}

function applyNetworkGraphSelection({ nodeId = "", edgeId = "" }) {
    state.networkGraph.selectedNodeId = String(nodeId ?? "");
    state.networkGraph.selectedEdgeId = String(edgeId ?? "");

    if (state.networkGraph.selectedNodeId) {
        const node = asObject(state.networkGraph.lookup.nodeById[state.networkGraph.selectedNodeId]);
        const typing = normalizeAttackSnapshot(node);
        const text = [
            `Node ${state.networkGraph.selectedNodeId}`,
            String(node.role ?? "").trim() ? `role: ${node.role}` : "",
            Number.isFinite(Number(node.incident_count)) ? `incidents: ${Number(node.incident_count)}` : "",
            `primary attack: ${typing.primaryClass}`,
            `confidence: ${fmtConfidence(typing.attackConfidence, 2)}`,
            `certainty: ${certaintyLevelLabel(typing.certaintyLevel)}`,
        ].filter(Boolean).join(" · ");
        setNetworkGraphSelectionText(text);
    } else if (state.networkGraph.selectedEdgeId) {
        const edge = asObject(state.networkGraph.lookup.edgeById[state.networkGraph.selectedEdgeId]);
        const typing = normalizeAttackSnapshot(edge);
        const source = String(edge.source ?? "--");
        const target = String(edge.target ?? "--");
        const text = [
            `Edge ${source} -> ${target}`,
            Number.isFinite(Number(edge.weight)) ? `weight: ${Number(edge.weight)}` : "",
            `primary attack: ${typing.primaryClass}`,
            `confidence: ${fmtConfidence(typing.attackConfidence, 2)}`,
            `certainty: ${certaintyLevelLabel(typing.certaintyLevel)}`,
        ].filter(Boolean).join(" · ");
        setNetworkGraphSelectionText(text);
    } else {
        setNetworkGraphSelectionText("");
    }
    syncNetworkGraphTableSelection();
}

function selectNetworkGraphNode(nodeId) {
    const normalized = String(nodeId ?? "").trim();
    if (!normalized) return;
    const network = state.networkGraph.instance;
    if (network) {
        markNetworkGraphInteraction(false);
        network.setSelection({ nodes: [normalized], edges: [] }, { highlightEdges: true });
        network.focus(normalized, {
            scale: 1.1,
            animation: { duration: 350, easingFunction: "easeInOutQuad" },
        });
        setTimeout(() => snapshotNetworkGraphViewState(), 380);
    }
    applyNetworkGraphSelection({ nodeId: normalized, edgeId: "" });
}

function selectNetworkGraphEdge(edgeId) {
    const normalized = String(edgeId ?? "").trim();
    if (!normalized) return;
    const network = state.networkGraph.instance;
    const edge = asObject(state.networkGraph.lookup.edgeById[normalized]);
    if (network) {
        markNetworkGraphInteraction(false);
        network.setSelection({ nodes: [], edges: [normalized] }, { highlightEdges: true });
        const source = String(edge.source ?? "").trim();
        const target = String(edge.target ?? "").trim();
        if (source && target) {
            network.fit({
                nodes: [source, target],
                animation: { duration: 350, easingFunction: "easeInOutQuad" },
            });
            setTimeout(() => snapshotNetworkGraphViewState(), 380);
        }
    }
    applyNetworkGraphSelection({ nodeId: "", edgeId: normalized });
}

function refreshNetworkGraphPhysicsButton() {
    const button = document.getElementById("networkGraphPhysicsToggle");
    if (!button) return;
    if (state.networkGraph.physicsEnabled) {
        button.innerHTML = '<i class="fa-solid fa-circle-pause"></i> Pause Physics';
        return;
    }
    button.innerHTML = '<i class="fa-solid fa-circle-play"></i> Resume Physics';
}

function setNetworkGraphPhysicsEnabled(enabled) {
    state.networkGraph.physicsEnabled = !!enabled;
    if (state.networkGraph.instance) {
        state.networkGraph.instance.setOptions({
            physics: { enabled: state.networkGraph.physicsEnabled },
        });
    }
    refreshNetworkGraphPhysicsButton();
}

function fitNetworkGraph() {
    if (!state.networkGraph.instance) return;
    markNetworkGraphInteraction(false);
    state.networkGraph.instance.fit({
        animation: { duration: 350, easingFunction: "easeInOutQuad" },
    });
    setTimeout(() => snapshotNetworkGraphViewState(), 380);
}

function renderNetworkGraphTables(payload, prepared = null) {
    const nodeBody = document.getElementById("networkNodesRows");
    const edgeBody = document.getElementById("networkEdgesRows");
    if (!nodeBody || !edgeBody) return;
    const data = prepared || prepareNetworkGraphData(payload);
    const { nodes, edges, searchTerm } = data;

    nodeBody.innerHTML = nodes.map((n) => {
        const typing = normalizeAttackSnapshot(n);
        const nodeId = String(n.id ?? "");
        return `<tr class="interactive network-node-row" data-node-id="${escapeHtml(nodeId)}">
            <td class="mono">${escapeHtml(nodeId)}</td>
            <td>${escapeHtml(n.role)}</td>
            <td>${escapeHtml(typing.primaryClass)}</td>
            <td>${escapeHtml(fmtConfidence(typing.attackConfidence, 2))}</td>
            <td>${escapeHtml(certaintyLevelLabel(typing.certaintyLevel))}</td>
        </tr>`;
    }).join("") || `<tr><td colspan="5">${escapeHtml(buildEmptyStateMessage("No nodes", searchTerm))}</td></tr>`;
    edgeBody.innerHTML = edges.map((e) => {
        const typing = normalizeAttackSnapshot(e);
        const source = String(e.source ?? "");
        const target = String(e.target ?? "");
        const edgeId = networkGraphEdgeId(source, target);
        return `<tr class="interactive network-edge-row" data-edge-id="${escapeHtml(edgeId)}" data-source="${escapeHtml(source)}" data-target="${escapeHtml(target)}">
            <td class="mono">${escapeHtml(source)}</td>
            <td class="mono">${escapeHtml(target)}</td>
            <td>${escapeHtml(e.weight)}</td>
            <td>${escapeHtml(typing.primaryClass)}</td>
            <td>${escapeHtml(fmtConfidence(typing.attackConfidence, 2))}</td>
            <td>${escapeHtml(certaintyLevelLabel(typing.certaintyLevel))}</td>
        </tr>`;
    }).join("") || `<tr><td colspan="6">${escapeHtml(buildEmptyStateMessage("No edges", searchTerm))}</td></tr>`;

    nodeBody.querySelectorAll(".network-node-row").forEach((row) => {
        row.addEventListener("click", () => selectNetworkGraphNode(row.dataset.nodeId));
    });
    edgeBody.querySelectorAll(".network-edge-row").forEach((row) => {
        row.addEventListener("click", () => selectNetworkGraphEdge(row.dataset.edgeId));
    });
    syncNetworkGraphTableSelection();
}

function renderNetworkGraphVisualization(payload, prepared = null) {
    const canvas = document.getElementById("networkGraphCanvas");
    if (!canvas) return;
    const data = prepared || prepareNetworkGraphData(payload);
    const hasVisNetwork = !!(window.vis && typeof window.vis.Network === "function" && typeof window.vis.DataSet === "function");

    if (!hasVisNetwork) {
        if (state.networkGraph.instance) {
            state.networkGraph.instance.destroy();
            state.networkGraph.instance = null;
        }
        canvas.innerHTML = `<div class="graph-placeholder">Graph library unavailable. Tables remain available.</div>`;
        setNetworkGraphStatus("Graph library failed to load. Showing table fallback.", "error");
        return;
    }

    const { nodes, edges } = data;
    if (!nodes.length) {
        if (state.networkGraph.instance) {
            state.networkGraph.instance.destroy();
            state.networkGraph.instance = null;
        }
        canvas.innerHTML = `<div class="graph-placeholder">${escapeHtml(buildEmptyStateMessage("No graph nodes to visualize", data.searchTerm))}</div>`;
        applyNetworkGraphSelection({ nodeId: "", edgeId: "" });
        setNetworkGraphStatus("");
        return;
    }

    const nodeById = {};
    const edgeById = {};
    if (state.networkGraph.instance) {
        snapshotNetworkGraphState();
    }
    const savedPositions = asObject(state.networkGraph.persistentNodePositions);
    const visNodes = nodes.map((node) => {
        const id = String(node.id ?? "").trim();
        const role = String(node.role ?? "").trim();
        const typing = normalizeAttackSnapshot(node);
        const certaintyLevel = normalizeCertaintyLevel(typing.certaintyLevel);
        const incidentCount = Math.max(1, Number(node.incident_count ?? 1) || 1);
        const roleColor = role === "attacker" ? "#ef4444" : "#3b82f6";
        const certaintyBorder = certaintyLevel === "certain"
            ? "#10b981"
            : (certaintyLevel === "probable" ? "#f59e0b" : "#64748b");
        const savedPosition = asObject(savedPositions[id]);
        const savedX = Number(savedPosition.x);
        const savedY = Number(savedPosition.y);
        const positionAttrs = (Number.isFinite(savedX) && Number.isFinite(savedY))
            ? { x: savedX, y: savedY }
            : {};
        nodeById[id] = node;
        return {
            id,
            label: String(node.label ?? id),
            value: incidentCount,
            title: [
                `IP: ${id}`,
                role ? `Role: ${role}` : "",
                `Incidents: ${incidentCount}`,
                `Primary attack: ${typing.primaryClass}`,
                `Confidence: ${fmtConfidence(typing.attackConfidence, 2)}`,
                `Certainty: ${certaintyLevelLabel(certaintyLevel)}`,
            ].filter(Boolean).join("\n"),
            color: {
                background: roleColor,
                border: certaintyBorder,
                highlight: { background: roleColor, border: "#f8fafc" },
            },
            font: { color: "#f8fafc" },
            ...positionAttrs,
        };
    });
    const visEdges = edges.map((edge) => {
        const source = String(edge.source ?? "").trim();
        const target = String(edge.target ?? "").trim();
        const id = networkGraphEdgeId(source, target);
        const typing = normalizeAttackSnapshot(edge);
        const certaintyLevel = normalizeCertaintyLevel(typing.certaintyLevel);
        const certaintyColor = certaintyLevel === "certain"
            ? "#10b981"
            : (certaintyLevel === "probable" ? "#f59e0b" : "#94a3b8");
        const weight = Math.max(1, Number(edge.weight ?? 1) || 1);
        edgeById[id] = edge;
        return {
            id,
            from: source,
            to: target,
            value: weight,
            width: Math.min(10, Math.max(1, weight)),
            arrows: "to",
            color: { color: certaintyColor, highlight: "#3b82f6" },
            title: [
                `${source} -> ${target}`,
                `Weight: ${weight}`,
                `Primary attack: ${typing.primaryClass}`,
                `Confidence: ${fmtConfidence(typing.attackConfidence, 2)}`,
                `Certainty: ${certaintyLevelLabel(certaintyLevel)}`,
            ].join("\n"),
        };
    });
    state.networkGraph.lookup = { nodeById, edgeById };

    const visData = {
        nodes: new window.vis.DataSet(visNodes),
        edges: new window.vis.DataSet(visEdges),
    };
    const options = {
        nodes: {
            shape: "dot",
            scaling: { min: 10, max: 34 },
            borderWidth: 2,
        },
        edges: {
            smooth: { type: "dynamic" },
            scaling: { min: 1, max: 10 },
        },
        interaction: {
            hover: true,
            tooltipDelay: 180,
            navigationButtons: true,
            keyboard: true,
        },
        physics: {
            enabled: !!state.networkGraph.physicsEnabled,
            stabilization: { iterations: 120 },
        },
    };

    if (!state.networkGraph.instance) {
        canvas.innerHTML = "";
        state.networkGraph.instance = new window.vis.Network(canvas, visData, options);
        state.networkGraph.instance.on("select", (params) => {
            const nodeId = asArray(params.nodes)[0] ? String(asArray(params.nodes)[0]) : "";
            const edgeId = asArray(params.edges)[0] ? String(asArray(params.edges)[0]) : "";
            applyNetworkGraphSelection({ nodeId, edgeId });
        });
        state.networkGraph.instance.on("deselectNode", () => applyNetworkGraphSelection({ nodeId: "", edgeId: "" }));
        state.networkGraph.instance.on("deselectEdge", () => applyNetworkGraphSelection({ nodeId: "", edgeId: "" }));
        state.networkGraph.instance.on("dragStart", () => {
            markNetworkGraphInteraction(true);
        });
        state.networkGraph.instance.on("dragging", () => {
            markNetworkGraphInteraction(true);
        });
        state.networkGraph.instance.on("dragEnd", (params) => {
            markNetworkGraphInteraction(false);
            snapshotNetworkGraphViewState();
            if (params && params.nodes && params.nodes.length) {
                snapshotNetworkGraphNodePositions();
            }
        });
        state.networkGraph.instance.on("zoom", () => {
            markNetworkGraphInteraction(false);
            snapshotNetworkGraphViewState();
        });
    } else {
        state.networkGraph.instance.setData(visData);
        state.networkGraph.instance.setOptions(options);
    }
    restoreNetworkGraphViewState();

    const statusMessages = [];
    if (data.searchFallbackApplied) {
        statusMessages.push(
            `No topology matches for "${state.searchTerm.trim()}". Showing full graph (${data.totalNodeAvailable} nodes / ${data.totalEdgeAvailable} edges).`
        );
    }
    if (data.truncatedNodes || data.truncatedEdges) {
        statusMessages.push(
            `Showing top ${nodes.length}/${data.totalNodeMatches} nodes and ${edges.length}/${data.totalEdgeMatches} edges for readability.`
        );
    }
    if (statusMessages.length) {
        setNetworkGraphStatus(statusMessages.join(" "), "pending");
    } else {
        setNetworkGraphStatus("");
    }
    refreshNetworkGraphPhysicsButton();
    syncNetworkGraphTableSelection();
}

function renderNetworkGraphView(payload) {
    const prepared = prepareNetworkGraphData(payload);
    renderNetworkGraphTables(payload, prepared);
    renderNetworkGraphVisualization(payload, prepared);
}

function threatIntelRowKey(item) {
    const safeItem = asObject(item);
    return [
        String(safeItem.incident_id ?? "").trim(),
        String(safeItem.ip ?? "").trim(),
        String(safeItem.role ?? "").trim(),
    ].join("|");
}

function threatIntelRiskColor(risk) {
    const normalized = String(risk ?? "").trim().toLowerCase();
    if (normalized === "high") return "#ef4444";
    if (normalized === "medium") return "#f59e0b";
    if (normalized === "low") return "#10b981";
    return "#64748b";
}

function setThreatIntelMapStatus(message = "", variant = "") {
    setStatusMessage("threatIntelMapStatus", message, variant);
}

function renderThreatIntelKpis(payload) {
    const safePayload = asObject(payload);
    const analytics = asObject(safePayload.analytics);
    const totals = asObject(analytics.totals);
    const meta = asObject(safePayload.meta);
    const providerHits = asObject(meta.provider_hits);
    const uniqueIps = Number(totals.unique_ips || meta.unique_ips || 0);
    const publicIps = Number(totals.public_ips || 0);
    const withVulns = Number(totals.with_vulnerabilities || 0);
    const shodanHits = Number(providerHits.shodan || 0);
    const kpiUniqueIps = document.getElementById("tiKpiUniqueIps");
    const kpiPublicIps = document.getElementById("tiKpiPublicIps");
    const kpiVulns = document.getElementById("tiKpiVulns");
    const kpiShodanHits = document.getElementById("tiKpiShodanHits");
    if (kpiUniqueIps) kpiUniqueIps.textContent = fmtNumber(uniqueIps);
    if (kpiPublicIps) kpiPublicIps.textContent = fmtNumber(publicIps);
    if (kpiVulns) kpiVulns.textContent = fmtNumber(withVulns);
    if (kpiShodanHits) kpiShodanHits.textContent = fmtNumber(shodanHits);
}

function upsertThreatIntelChart(signatureKey, chartRef, canvasId, type, data, options = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return chartRef;
    const signature = chartSignature({ type, data, options });
    if (state.chartSignatures[signatureKey] === signature) {
        return chartRef;
    }
    state.chartSignatures[signatureKey] = signature;
    if (!chartRef) {
        return new Chart(canvas.getContext("2d"), {
            type,
            data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                ...options,
            },
        });
    }
    chartRef.data = data;
    chartRef.options = {
        ...chartRef.options,
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        ...options,
    };
    chartRef.update("none");
    return chartRef;
}

function renderThreatIntelCharts(payload) {
    const analytics = asObject(asObject(payload).analytics);
    const riskRows = asArray(analytics.risk_distribution);
    const riskLabels = riskRows.map((entry) => String(asObject(entry).label ?? "").trim()).filter(Boolean);
    const riskValues = riskRows.map((entry) => Number(asObject(entry).count || 0));
    const riskData = riskLabels.length
        ? {
            labels: riskLabels,
            datasets: [{ data: riskValues, backgroundColor: riskLabels.map((label) => threatIntelRiskColor(label)) }],
        }
        : { labels: ["No risk data"], datasets: [{ data: [1], backgroundColor: ["#374151"] }] };
    threatIntelRiskChart = upsertThreatIntelChart(
        "threatIntelRisk",
        threatIntelRiskChart,
        "threatIntelRiskChart",
        "doughnut",
        riskData,
        { plugins: { legend: { position: "bottom" } } }
    );

    const countryRows = asArray(analytics.top_countries);
    const countryLabels = countryRows.map((entry) => String(asObject(entry).label ?? "").trim()).filter(Boolean);
    const countryValues = countryRows.map((entry) => Number(asObject(entry).count || 0));
    const countryData = countryLabels.length
        ? {
            labels: countryLabels,
            datasets: [{ label: "IPs", data: countryValues, backgroundColor: "#3b82f6" }],
        }
        : { labels: ["No data"], datasets: [{ label: "IPs", data: [0], backgroundColor: "#374151" }] };
    threatIntelCountryChart = upsertThreatIntelChart(
        "threatIntelCountry",
        threatIntelCountryChart,
        "threatIntelCountryChart",
        "bar",
        countryData,
        { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    );

    const portRows = asArray(analytics.top_ports);
    const portLabels = portRows.map((entry) => String(asObject(entry).port ?? "").trim()).filter(Boolean);
    const portValues = portRows.map((entry) => Number(asObject(entry).count || 0));
    const portData = portLabels.length
        ? {
            labels: portLabels,
            datasets: [{ label: "Occurrences", data: portValues, backgroundColor: "#8b5cf6" }],
        }
        : { labels: ["No data"], datasets: [{ label: "Occurrences", data: [0], backgroundColor: "#374151" }] };
    threatIntelPortChart = upsertThreatIntelChart(
        "threatIntelPorts",
        threatIntelPortChart,
        "threatIntelPortChart",
        "bar",
        portData,
        { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    );

    const vulnRows = asArray(analytics.vulnerability_severity);
    const vulnLabels = vulnRows.map((entry) => String(asObject(entry).severity ?? "").trim()).filter(Boolean);
    const vulnValues = vulnRows.map((entry) => Number(asObject(entry).count || 0));
    const vulnColors = vulnLabels.map((label) => {
        const normalized = label.toLowerCase();
        if (normalized === "critical") return "#dc2626";
        if (normalized === "high") return "#ef4444";
        if (normalized === "medium") return "#f59e0b";
        if (normalized === "low") return "#10b981";
        return "#64748b";
    });
    const vulnData = vulnLabels.length
        ? { labels: vulnLabels, datasets: [{ label: "CVEs", data: vulnValues, backgroundColor: vulnColors }] }
        : { labels: ["No data"], datasets: [{ label: "CVEs", data: [0], backgroundColor: "#374151" }] };
    threatIntelVulnChart = upsertThreatIntelChart(
        "threatIntelVuln",
        threatIntelVulnChart,
        "threatIntelVulnChart",
        "bar",
        vulnData,
        { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    );
}

function ensureThreatIntelMap() {
    const canvas = document.getElementById("threatIntelMapCanvas");
    if (!canvas) return null;
    const hasLeaflet = !!(window.L && typeof window.L.map === "function");
    if (!hasLeaflet) {
        setThreatIntelMapStatus("Map library failed to load. Charts and table remain available.", "error");
        return null;
    }
    if (!state.threatIntel.map.instance) {
        const map = window.L.map(canvas, { zoomControl: true, preferCanvas: true }).setView(
            [THREAT_INTEL_MAP_DEFAULT_VIEW.lat, THREAT_INTEL_MAP_DEFAULT_VIEW.lng],
            THREAT_INTEL_MAP_DEFAULT_VIEW.zoom
        );
        window.L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
            attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
            maxZoom: 10,
            minZoom: 2,
        }).addTo(map);
        const layerGroup = window.L.layerGroup().addTo(map);
        map.on("moveend zoomend", () => {
            const center = map.getCenter();
            state.threatIntel.map.viewState = {
                center: { lat: Number(center.lat), lng: Number(center.lng) },
                zoom: Number(map.getZoom()),
            };
        });
        state.threatIntel.map.instance = map;
        state.threatIntel.map.layerGroup = layerGroup;
    }
    return state.threatIntel.map.instance;
}

function threatIntelMapMarkerStyle(point, { isSelected = false, isFocused = false } = {}) {
    const safePoint = asObject(point);
    const role = String(safePoint.role ?? "unknown").trim().toLowerCase();
    const markerColor = threatIntelRiskColor(safePoint.risk);
    if (isSelected || isFocused) {
        return {
            radius: 10,
            color: markerColor,
            fillColor: markerColor,
            fillOpacity: 0.92,
            weight: 2.75,
        };
    }
    return {
        radius: role === "attacker" ? 8 : 7,
        color: markerColor,
        fillColor: markerColor,
        fillOpacity: 0.75,
        weight: role === "attacker" ? 2 : 1.25,
    };
}

function threatIntelMapPopupContent(point) {
    const safePoint = asObject(point);
    const ip = String(safePoint.ip ?? "").trim();
    return `
        <div class="mono">${escapeHtml(ip)}</div>
        <div>role: ${escapeHtml(String(safePoint.role ?? "unknown"))}</div>
        <div>intel risk: ${escapeHtml(String(safePoint.risk ?? "unknown"))}</div>
        <div>incidents: ${escapeHtml(fmtNumber(safePoint.incident_count ?? 0))}</div>
        <div>vulns: ${escapeHtml(fmtNumber(safePoint.vuln_count ?? 0))}</div>
    `;
}

function focusThreatIntelMapIp(ip, { announceFailure = true } = {}) {
    const normalizedIp = String(ip ?? "").trim();
    if (!normalizedIp || normalizedIp === "--") return false;
    const map = state.threatIntel.map.instance;
    const marker = asObject(state.threatIntel.map.markersByIp)[normalizedIp];
    if (!map || !marker) {
        if (announceFailure) {
            setThreatIntelMapStatus(`IP ${normalizedIp} has no mappable coordinates in current threat-intel results.`, "pending");
        }
        return false;
    }
    const zoom = Number(map.getZoom());
    map.flyTo(
        marker.getLatLng(),
        Number.isFinite(zoom) ? Math.max(zoom, THREAT_INTEL_MAP_MIN_FOCUS_ZOOM) : THREAT_INTEL_MAP_MIN_FOCUS_ZOOM,
        { animate: true, duration: 0.5 }
    );
    marker.openPopup();
    state.threatIntel.pendingFocusIp = "";
    state.threatIntel.map.focusedIp = normalizedIp;
    state.threatIntel.map.hasFittedBounds = true;
    setThreatIntelMapStatus(`Focused on ${normalizedIp}.`, "success");
    return true;
}

function fitThreatIntelMapToMarkers({ announce = true } = {}) {
    const map = ensureThreatIntelMap();
    if (!map) return false;
    const markerEntries = Object.values(asObject(state.threatIntel.map.markersByIp))
        .map((marker) => (marker && typeof marker.getLatLng === "function" ? marker.getLatLng() : null))
        .filter((point) => !!point);
    if (!markerEntries.length) {
        if (announce) {
            setThreatIntelMapStatus("No mappable public IPs available to fit.", "pending");
        }
        return false;
    }
    map.fitBounds(markerEntries, { padding: [24, 24], maxZoom: 5, animate: true });
    state.threatIntel.map.hasFittedBounds = true;
    if (announce) {
        setThreatIntelMapStatus(`Fitted map to ${markerEntries.length} endpoints.`, "success");
    }
    return true;
}

function resetThreatIntelMapView() {
    const map = ensureThreatIntelMap();
    if (!map) return false;
    map.setView(
        [THREAT_INTEL_MAP_DEFAULT_VIEW.lat, THREAT_INTEL_MAP_DEFAULT_VIEW.lng],
        THREAT_INTEL_MAP_DEFAULT_VIEW.zoom,
        { animate: true }
    );
    state.threatIntel.map.hasFittedBounds = true;
    state.threatIntel.map.focusedIp = "";
    setThreatIntelMapStatus("Map view reset.", "success");
    return true;
}

function focusThreatIntelSelectedRow({ openView = false } = {}) {
    const payload = asObject(state.cachedViewData.threatMap);
    const items = asArray(payload.items);
    if (!items.length) {
        setThreatIntelMapStatus("No threat-intel rows are available to focus.", "pending");
        return false;
    }
    const selected = items.find((item) => threatIntelRowKey(item) === state.threatIntel.selectedRowKey) || items[0];
    const ip = String(asObject(selected).ip ?? "").trim();
    if (!ip || ip === "--") {
        setThreatIntelMapStatus("Selected row has no IP to focus.", "pending");
        return false;
    }
    requestThreatIntelFocus(ip, { openView, applySearch: false });
    return true;
}

function renderThreatIntelMap(payload) {
    const map = ensureThreatIntelMap();
    if (!map) return;
    const safePayload = asObject(payload);
    const points = asArray(safePayload.map_points).filter((point) => point && typeof point === "object");
    const layerGroup = state.threatIntel.map.layerGroup;
    const markerByIp = asObject(state.threatIntel.map.markersByIp);
    const retainedIps = new Set();
    const bounds = [];
    const selectedItem = asArray(safePayload.items).find((item) => threatIntelRowKey(item) === state.threatIntel.selectedRowKey)
        || null;
    const selectedIp = selectedItem ? String(asObject(selectedItem).ip ?? "").trim() : "";
    const focusedIp = String(state.threatIntel.map.focusedIp ?? "").trim();
    points.forEach((point) => {
        const safePoint = asObject(point);
        const lat = Number(safePoint.latitude);
        const lng = Number(safePoint.longitude);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;
        const ip = String(safePoint.ip ?? "").trim();
        if (!ip) return;
        retainedIps.add(ip);
        const markerStyle = threatIntelMapMarkerStyle(safePoint, {
            isSelected: !!selectedIp && ip === selectedIp,
            isFocused: !!focusedIp && ip === focusedIp,
        });
        let marker = markerByIp[ip];
        if (marker && typeof marker.setLatLng === "function") {
            marker.setLatLng([lat, lng]);
            if (typeof marker.setStyle === "function") {
                marker.setStyle(markerStyle);
            }
            if (typeof marker.setPopupContent === "function") {
                marker.setPopupContent(threatIntelMapPopupContent(safePoint));
            }
        } else {
            marker = window.L.circleMarker([lat, lng], markerStyle);
            marker.bindPopup(threatIntelMapPopupContent(safePoint));
            markerByIp[ip] = marker;
        }
        if (layerGroup && typeof layerGroup.hasLayer === "function") {
            if (!layerGroup.hasLayer(marker)) {
                marker.addTo(layerGroup);
            }
        } else if (!map.hasLayer(marker)) {
            marker.addTo(map);
        }
        bounds.push([lat, lng]);
    });
    Object.entries(markerByIp).forEach(([ip, marker]) => {
        if (retainedIps.has(ip)) return;
        if (layerGroup && typeof layerGroup.removeLayer === "function") {
            layerGroup.removeLayer(marker);
        } else if (map.hasLayer(marker)) {
            map.removeLayer(marker);
        }
        delete markerByIp[ip];
        if (state.threatIntel.map.focusedIp === ip) {
            state.threatIntel.map.focusedIp = "";
        }
    });

    setTimeout(() => map.invalidateSize(false), 0);
    if (!bounds.length) {
        setThreatIntelMapStatus("No mappable public IPs in current threat-intel payload.", "pending");
        return;
    }
    if (!state.threatIntel.map.hasFittedBounds) {
        map.fitBounds(bounds, { padding: [24, 24], maxZoom: 5, animate: false });
        state.threatIntel.map.hasFittedBounds = true;
    }
    const focusIp = String(state.threatIntel.pendingFocusIp ?? "").trim();
    if (focusIp && focusThreatIntelMapIp(focusIp, { announceFailure: false })) {
        return;
    }
    if (focusIp) {
        const ipExistsInRows = asArray(safePayload.items).some((item) => String(asObject(item).ip ?? "").trim() === focusIp);
        state.threatIntel.pendingFocusIp = "";
        if (ipExistsInRows) {
            setThreatIntelMapStatus(`IP ${focusIp} is present but currently has no map coordinates.`, "pending");
        } else {
            setThreatIntelMapStatus(`IP ${focusIp} is not present in current threat-intel rows.`, "pending");
        }
        return;
    }
    setThreatIntelMapStatus(`Mapped ${bounds.length} public threat-intel endpoints.`);
}

function renderThreatIntelDetail(item) {
    const summary = document.getElementById("threatIntelDetailSummary");
    const serviceList = document.getElementById("threatIntelServiceList");
    const vulnList = document.getElementById("threatIntelVulnList");
    if (!summary || !serviceList || !vulnList) return;
    if (!item || typeof item !== "object") {
        summary.textContent = "Select a Threat Intel row to inspect service and CVE detail.";
        serviceList.innerHTML = '<li class="list-empty">No service details selected</li>';
        vulnList.innerHTML = '<li class="list-empty">No CVE details selected</li>';
        return;
    }
    const safeItem = asObject(item);
    const location = [String(safeItem.city ?? "").trim(), String(safeItem.country ?? "").trim()].filter(Boolean).join(", ") || "--";
    const organization = [String(safeItem.org ?? "").trim(), String(safeItem.asn ?? "").trim()].filter(Boolean).join(" / ") || "--";
    const servicesCount = Number(safeItem.services_count || 0);
    const vulnCount = Number(safeItem.vuln_count || 0);
    summary.textContent = `${safeItem.ip || "--"} (${safeItem.role || "unknown"}) · ${location} · ${organization} · intel risk: ${safeItem.risk || "unknown"} · ${servicesCount} services · ${vulnCount} CVEs`;
    const services = asArray(safeItem.services).slice(0, 8);
    serviceList.innerHTML = services.length
        ? services.map((entry) => {
            const safeEntry = asObject(entry);
            const port = String(safeEntry.port ?? "--");
            const transport = String(safeEntry.transport ?? "--");
            const product = String(safeEntry.product ?? "--");
            const version = String(safeEntry.version ?? "--");
            const label = `${port}/${transport} · ${product}${version !== "--" ? ` ${version}` : ""}`;
            return `<li>${escapeHtml(label)}</li>`;
        }).join("")
        : '<li class="list-empty">No service details available for this row</li>';
    const vulns = asArray(safeItem.vuln_details).slice(0, 8);
    vulnList.innerHTML = vulns.length
        ? vulns.map((entry) => {
            const safeEntry = asObject(entry);
            const vulnId = String(safeEntry.id ?? "--");
            const severity = String(safeEntry.severity ?? "unknown").toUpperCase();
            const cvss = Number(safeEntry.cvss);
            const cvssLabel = Number.isFinite(cvss) && cvss >= 0 ? `CVSS ${cvss.toFixed(1)}` : "CVSS --";
            return `<li>${escapeHtml(`${vulnId} · ${severity} · ${cvssLabel}`)}</li>`;
        }).join("")
        : '<li class="list-empty">No CVE details available for this row</li>';
}

function renderThreatMapTable(payload) {
    const safePayload = asObject(payload);
    const body = document.getElementById("threatMapRows");
    if (!body) return;
    const searchTerm = getSearchTerm();
    const allItems = asArray(safePayload.items).filter((item) => item && typeof item === "object");
    const items = filterBySearch(allItems, searchTerm);
    const pendingFocusIp = String(state.threatIntel.pendingFocusIp ?? "").trim();
    if (!allItems.length) {
        body.innerHTML = "<tr><td colspan=\"10\">No threat-intel rows</td></tr>";
        state.threatIntel.selectedRowKey = "";
        renderThreatIntelDetail(null);
        return;
    }

    if (pendingFocusIp) {
        const preferredByRole = allItems.find((item) => {
            const safeItem = asObject(item);
            return String(safeItem.ip ?? "").trim() === pendingFocusIp && String(safeItem.role ?? "").trim().toLowerCase() === "attacker";
        });
        const preferredAny = preferredByRole || allItems.find((item) => String(asObject(item).ip ?? "").trim() === pendingFocusIp);
        if (preferredAny) {
            state.threatIntel.selectedRowKey = threatIntelRowKey(preferredAny);
        }
    }
    const selectedRowExists = allItems.some((item) => threatIntelRowKey(item) === state.threatIntel.selectedRowKey);
    if (!selectedRowExists) {
        state.threatIntel.selectedRowKey = threatIntelRowKey(allItems[0]);
    }
    const selectedItemFromAll = allItems.find((item) => threatIntelRowKey(item) === state.threatIntel.selectedRowKey) || null;
    if (!items.length) {
        body.innerHTML = `<tr><td colspan="10">${escapeHtml(buildEmptyStateMessage("No threat-intel rows", searchTerm))}</td></tr>`;
        renderThreatIntelDetail(selectedItemFromAll);
        return;
    }
    body.innerHTML = items.map((item) => {
        const safeItem = asObject(item);
        const rowKey = threatIntelRowKey(safeItem);
        const certainty = asObject(safeItem.attack_certainty);
        const certaintyLevel = normalizeCertaintyLevel(certainty.level);
        const organization = [String(safeItem.org ?? "").trim(), String(safeItem.asn ?? "").trim()]
            .filter(Boolean)
            .join(" / ") || "--";
        const provider = String(safeItem.intel_source ?? "fallback");
        const providerStatus = String(safeItem.provider_status ?? "").trim();
        const providerLabel = providerStatus && providerStatus !== "ok"
            ? `${provider} (${providerStatus})`
            : provider;
        const updated = String(safeItem.last_update ?? "").trim();
        const updatedLabel = updated ? updated.replace("T", " ").slice(0, 19) : "--";
        const geo = [String(safeItem.city ?? "").trim(), String(safeItem.country ?? "").trim()].filter(Boolean).join(", ") || "--";
        const serviceSummary = Number(safeItem.services_count || 0) > 0
            ? `${fmtNumber(safeItem.services_count)} services`
            : (String(safeItem.open_ports_summary ?? "--") !== "--" ? `ports: ${safeItem.open_ports_summary}` : "--");
        const vulnSummary = Number(safeItem.vuln_count || 0) > 0
            ? `${fmtNumber(safeItem.vuln_count)} CVEs`
            : "--";
        const selectedClass = rowKey === state.threatIntel.selectedRowKey ? " is-selected" : "";
        const ip = String(safeItem.ip ?? "").trim();
        const canJumpToMap = !!ip && ip !== "--";
        return `
        <tr class="interactive threat-intel-row${selectedClass}" data-row-key="${escapeHtml(rowKey)}">
            <td class="mono">${escapeHtml(safeItem.incident_id)}</td>
            <td class="mono">${canJumpToMap
                ? `<button type="button" class="table-link-btn threat-intel-map-jump" data-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</button>`
                : escapeHtml(safeItem.ip)}</td>
            <td>${escapeHtml(safeItem.role)}</td>
            <td>${escapeHtml(providerLabel)}</td>
            <td>${escapeHtml(organization)}</td>
            <td>${escapeHtml(geo)}</td>
            <td>${escapeHtml(serviceSummary)}</td>
            <td>${escapeHtml(vulnSummary)}</td>
            <td>
                <div class="cell-stack">
                    <div>${escapeHtml(String(safeItem.risk ?? "unknown"))}</div>
                    <div class="cell-meta">attack certainty: ${escapeHtml(certaintyLevelLabel(certaintyLevel))}</div>
                </div>
            </td>
            <td class="mono">${escapeHtml(updatedLabel)}</td>
        </tr>
    `;
    }).join("");
    body.querySelectorAll(".threat-intel-row").forEach((row) => {
        row.addEventListener("click", () => {
            state.threatIntel.selectedRowKey = String(row.dataset.rowKey ?? "");
            body.querySelectorAll(".threat-intel-row").forEach((entry) => {
                entry.classList.toggle("is-selected", entry.dataset.rowKey === state.threatIntel.selectedRowKey);
            });
            const selected = allItems.find((item) => threatIntelRowKey(item) === state.threatIntel.selectedRowKey);
            renderThreatIntelDetail(selected || null);
            renderThreatIntelMap(safePayload);
        });
    });
    body.querySelectorAll(".threat-intel-map-jump").forEach((button) => {
        ["click", "mousedown", "keydown"].forEach((eventName) => {
            button.addEventListener(eventName, (event) => {
                event.stopPropagation();
            });
        });
        button.addEventListener("click", () => {
            const ip = String(button.dataset.ip ?? "").trim();
            requestThreatIntelFocus(ip, { openView: false, applySearch: false });
            const selected = allItems.find((item) => String(asObject(item).ip ?? "").trim() === ip) || null;
            if (selected) {
                state.threatIntel.selectedRowKey = threatIntelRowKey(selected);
                body.querySelectorAll(".threat-intel-row").forEach((entry) => {
                    entry.classList.toggle("is-selected", entry.dataset.rowKey === state.threatIntel.selectedRowKey);
                });
                renderThreatIntelDetail(selected);
            }
            renderThreatIntelMap(safePayload);
        });
    });
    const selectedItem = allItems.find((item) => threatIntelRowKey(item) === state.threatIntel.selectedRowKey);
    renderThreatIntelDetail(selectedItem || null);
}

function renderThreatIntelView(payload) {
    const safePayload = asObject(payload);
    renderThreatIntelKpis(safePayload);
    renderThreatIntelCharts(safePayload);
    renderThreatMapTable(safePayload);
    renderThreatIntelMap(safePayload);
}

function formatHuntingMethodLabel(value) {
    return String(value ?? "")
        .trim()
        .replaceAll("_", " ")
        .replaceAll("-", " ")
        .replace(/\s+/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

function parseDelimitedValues(rawValue) {
    const seen = new Set();
    const normalized = [];
    String(rawValue ?? "")
        .split(/[\n,]+/)
        .map((value) => value.trim())
        .filter(Boolean)
        .forEach((value) => {
            const key = value.toLowerCase();
            if (seen.has(key)) return;
            seen.add(key);
            normalized.push(value);
        });
    return normalized;
}

function readMultiSelectValues(id) {
    const select = document.getElementById(id);
    if (!select) return [];
    return Array.from(select.selectedOptions)
        .map((option) => String(option.value ?? "").trim())
        .filter(Boolean);
}

function setMultiSelectOptions(id, values, { selectedValues = null } = {}) {
    const select = document.getElementById(id);
    if (!select) return;
    const normalizedValues = Array.from(new Set(
        asArray(values)
            .map((value) => String(value ?? "").trim())
            .filter(Boolean)
    ));
    const selectedSet = new Set(
        ((selectedValues === null ? readMultiSelectValues(id) : selectedValues))
            .map((value) => String(value ?? "").trim())
            .filter(Boolean)
    );
    select.innerHTML = normalizedValues.map((value) => `
        <option value="${escapeHtml(value)}"${selectedSet.has(value) ? " selected" : ""}>${escapeHtml(formatHuntingMethodLabel(value))}</option>
    `).join("");
}

function getSelectedScientificMethods() {
    return Array.from(document.querySelectorAll("#huntingScientificMethods input[name=\"huntingScientificMethod\"]:checked"))
        .map((input) => String(input.value ?? "").trim())
        .filter(Boolean);
}

function readOptionalNumberInput({ id, label, min = null, max = null, integer = false }) {
    const input = document.getElementById(id);
    const raw = String(input?.value ?? "").trim();
    if (!raw) return null;
    const value = Number(raw);
    if (!Number.isFinite(value)) {
        throw new Error(`${label} must be a valid number.`);
    }
    if (integer && !Number.isInteger(value)) {
        throw new Error(`${label} must be an integer.`);
    }
    if (min !== null && value < min) {
        throw new Error(`${label} must be >= ${min}.`);
    }
    if (max !== null && value > max) {
        throw new Error(`${label} must be <= ${max}.`);
    }
    return integer ? Math.trunc(value) : value;
}

function buildThreatHuntingQueryPayload() {
    const filters = {};
    const sourceIps = parseDelimitedValues(document.getElementById("huntingFilterSourceIps")?.value);
    const targetIps = parseDelimitedValues(document.getElementById("huntingFilterTargetIps")?.value);
    const attackClasses = parseDelimitedValues(document.getElementById("huntingFilterAttackClasses")?.value);
    const severities = readMultiSelectValues("huntingFilterSeverities");
    const certaintyLevels = readMultiSelectValues("huntingFilterCertaintyLevels");
    const triageStates = readMultiSelectValues("huntingFilterTriageStates");
    if (sourceIps.length) filters.source_ips = sourceIps;
    if (targetIps.length) filters.target_ips = targetIps;
    if (attackClasses.length) filters.attack_primary_classes = attackClasses;
    if (severities.length) filters.severities = severities;
    if (certaintyLevels.length) filters.certainty_levels = certaintyLevels;
    if (triageStates.length) filters.triage_states = triageStates;

    const addNumericFilter = (field, cfg) => {
        const value = readOptionalNumberInput(cfg);
        if (value !== null) filters[field] = value;
    };
    addNumericFilter("attack_confidence_gte", {
        id: "huntingFilterAttackConfidenceGte",
        label: "Attack confidence minimum",
        min: 0,
        max: 1,
    });
    addNumericFilter("attack_confidence_lte", {
        id: "huntingFilterAttackConfidenceLte",
        label: "Attack confidence maximum",
        min: 0,
        max: 1,
    });
    addNumericFilter("detection_confidence_gte", {
        id: "huntingFilterDetectionConfidenceGte",
        label: "Detection confidence minimum",
        min: 0,
        max: 1,
    });
    addNumericFilter("detection_confidence_lte", {
        id: "huntingFilterDetectionConfidenceLte",
        label: "Detection confidence maximum",
        min: 0,
        max: 1,
    });
    addNumericFilter("event_count_gte", {
        id: "huntingFilterEventCountGte",
        label: "Event count minimum",
        min: 0,
        integer: true,
    });
    addNumericFilter("event_count_lte", {
        id: "huntingFilterEventCountLte",
        label: "Event count maximum",
        min: 0,
        integer: true,
    });
    addNumericFilter("bytes_gte", {
        id: "huntingFilterBytesGte",
        label: "Bytes minimum",
        min: 0,
        integer: true,
    });
    addNumericFilter("bytes_lte", {
        id: "huntingFilterBytesLte",
        label: "Bytes maximum",
        min: 0,
        integer: true,
    });
    addNumericFilter("packets_gte", {
        id: "huntingFilterPacketsGte",
        label: "Packets minimum",
        min: 0,
        integer: true,
    });
    addNumericFilter("packets_lte", {
        id: "huntingFilterPacketsLte",
        label: "Packets maximum",
        min: 0,
        integer: true,
    });

    const fromTimestamp = String(document.getElementById("huntingFilterFromTimestamp")?.value ?? "").trim();
    const toTimestamp = String(document.getElementById("huntingFilterToTimestamp")?.value ?? "").trim();
    const textContains = String(document.getElementById("huntingFilterTextContains")?.value ?? "").trim();
    if (fromTimestamp) filters.from_timestamp = fromTimestamp;
    if (toTimestamp) filters.to_timestamp = toTimestamp;
    if (textContains) filters.text_contains = textContains;

    const payload = {
        dsl: String(document.getElementById("huntingDslInput")?.value ?? "").trim(),
        limit: readOptionalNumberInput({
            id: "huntingFilterLimit",
            label: "Result limit",
            min: 1,
            max: 1000,
            integer: true,
        }) ?? 100,
        offset: readOptionalNumberInput({
            id: "huntingFilterOffset",
            label: "Result offset",
            min: 0,
            max: 2000,
            integer: true,
        }) ?? 0,
        scan_limit: readOptionalNumberInput({
            id: "huntingFilterScanLimit",
            label: "Scan limit",
            min: 1,
            max: 2000,
            integer: true,
        }) ?? 600,
    };
    if (Object.keys(filters).length) {
        payload.filters = filters;
    }

    const selectedMethods = getSelectedScientificMethods();
    const scientificMethods = {};
    if (selectedMethods.length) {
        scientificMethods.enabled = selectedMethods;
    }
    const maxScientificIncidents = readOptionalNumberInput({
        id: "huntingScientificMaxIncidents",
        label: "Scientific max incidents",
        min: 50,
        max: 2000,
        integer: true,
    });
    if (maxScientificIncidents !== null) {
        scientificMethods.max_incidents = maxScientificIncidents;
    }
    if (Object.keys(scientificMethods).length) {
        payload.scientific_methods = scientificMethods;
    }
    state.hunting.selectedScientificMethods = selectedMethods;
    return payload;
}

function appendThreatHuntingListParam(params, key, values) {
    asArray(values)
        .map((value) => String(value ?? "").trim())
        .filter(Boolean)
        .forEach((value) => params.append(key, value));
}

function buildThreatHuntingQueryParams(payload) {
    const safePayload = asObject(payload);
    const params = new URLSearchParams();
    const dsl = String(safePayload.dsl ?? "").trim();
    if (dsl) params.set("dsl", dsl);
    ["limit", "offset", "scan_limit"].forEach((key) => {
        const raw = Number(safePayload[key]);
        if (!Number.isFinite(raw)) return;
        params.set(key, String(Math.trunc(raw)));
    });

    const filters = asObject(safePayload.filters);
    [
        "source_ips",
        "target_ips",
        "severities",
        "attack_primary_classes",
        "certainty_levels",
        "triage_states",
    ].forEach((key) => appendThreatHuntingListParam(params, key, filters[key]));
    [
        "attack_confidence_gte",
        "attack_confidence_lte",
        "detection_confidence_gte",
        "detection_confidence_lte",
        "event_count_gte",
        "event_count_lte",
        "bytes_gte",
        "bytes_lte",
        "packets_gte",
        "packets_lte",
        "from_timestamp",
        "to_timestamp",
        "text_contains",
    ].forEach((key) => {
        const value = filters[key];
        if (value === undefined || value === null) return;
        const normalized = String(value).trim();
        if (normalized) params.set(key, normalized);
    });

    const scientificMethods = asObject(safePayload.scientific_methods);
    const enabledMethods = asArray(scientificMethods.enabled)
        .map((name) => String(name ?? "").trim())
        .filter(Boolean);
    if (enabledMethods.length) {
        params.set("methods", enabledMethods.join(","));
    }
    const maxIncidents = Number(scientificMethods.max_incidents);
    if (Number.isFinite(maxIncidents) && maxIncidents > 0) {
        params.set("scientific_max_incidents", String(Math.trunc(maxIncidents)));
    }
    return params;
}

function isThreatHuntingCompatibilityIssue(error) {
    const status = Number(error?.status);
    if (status === 404 || status === 405) return true;
    const message = String(error?.message ?? "");
    return /\b404\b/.test(message)
        || /\b405\b/.test(message)
        || /not found/i.test(message)
        || /method not allowed/i.test(message);
}

function isThreatHuntingQueryResponse(payload) {
    const safePayload = asObject(payload);
    return Array.isArray(safePayload.items)
        || Number.isFinite(Number(safePayload.total_matches))
        || !!safePayload.query;
}

function buildThreatHuntingEndpointUrl(basePath, params, extraParams = {}) {
    const merged = new URLSearchParams(params);
    Object.entries(asObject(extraParams)).forEach(([key, value]) => {
        if (value === undefined || value === null) return;
        merged.set(key, String(value));
    });
    const queryString = merged.toString();
    return queryString ? `${basePath}?${queryString}` : basePath;
}

function getThreatHuntingClientFallbackCaps() {
    const capabilities = asObject(state.hunting.capabilities);
    const capabilitiesMeta = asObject(capabilities.meta);
    const guardrails = Object.keys(asObject(capabilitiesMeta.query_guardrails)).length
        ? asObject(capabilitiesMeta.query_guardrails)
        : asObject(capabilitiesMeta.guardrails);
    const maxScanRaw = Number(guardrails.max_scan_incidents);
    const maxLimitRaw = Number(guardrails.max_result_limit);
    const maxScan = Number.isFinite(maxScanRaw) && maxScanRaw > 0
        ? Math.trunc(Math.min(maxScanRaw, HUNTING_CLIENT_FALLBACK_MAX_SCAN))
        : HUNTING_CLIENT_FALLBACK_MAX_SCAN;
    const maxLimit = Number.isFinite(maxLimitRaw) && maxLimitRaw > 0
        ? Math.trunc(Math.min(maxLimitRaw, HUNTING_CLIENT_FALLBACK_MAX_LIMIT))
        : HUNTING_CLIENT_FALLBACK_MAX_LIMIT;
    return { maxScan, maxLimit };
}

function normalizeThreatHuntingClientFilterValues(rawValue, fieldName, maxItems = 50) {
    if (rawValue === undefined || rawValue === null) return [];
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    const normalized = values
        .map((value) => String(value ?? "").trim())
        .filter(Boolean);
    if (normalized.length > maxItems) {
        throw new Error(`filters.${fieldName} exceeds max item count (${maxItems})`);
    }
    return normalized;
}

function parseThreatHuntingClientFilterTimestamp(rawValue, fieldName) {
    if (rawValue === undefined || rawValue === null || String(rawValue).trim() === "") return null;
    const parsed = new Date(String(rawValue).trim());
    if (Number.isNaN(parsed.getTime())) {
        throw new Error(`filters.${fieldName} must be ISO-8601`);
    }
    return parsed;
}

function normalizeThreatHuntingClientFilters(rawFilters) {
    if (rawFilters === undefined || rawFilters === null) return {};
    if (typeof rawFilters !== "object" || Array.isArray(rawFilters)) {
        throw new Error("filters must be a JSON object");
    }
    const filters = asObject(rawFilters);
    const sourceIps = normalizeThreatHuntingClientFilterValues(filters.source_ips, "source_ips");
    const targetIps = normalizeThreatHuntingClientFilterValues(filters.target_ips, "target_ips");
    const severities = normalizeThreatHuntingClientFilterValues(filters.severities, "severities");
    const attackPrimaryClasses = normalizeThreatHuntingClientFilterValues(
        filters.attack_primary_classes,
        "attack_primary_classes"
    );
    const certaintyLevelsRaw = normalizeThreatHuntingClientFilterValues(filters.certainty_levels, "certainty_levels");
    const triageStatesRaw = normalizeThreatHuntingClientFilterValues(filters.triage_states, "triage_states");
    const certaintyLevels = Array.from(new Set(certaintyLevelsRaw.map((value) => normalizeCertaintyLevel(value))));
    const triageStates = Array.from(new Set(triageStatesRaw.map((value) => {
        const normalized = normalizeTriageState(value);
        const raw = String(value ?? "").trim().toLowerCase();
        if (normalized === "open" && raw !== "" && raw !== "open") {
            throw new Error("Invalid triage state.");
        }
        return normalized;
    })));

    const parseOptionalNumber = (value) => {
        if (value === undefined || value === null || String(value).trim() === "") return null;
        const numeric = Number(value);
        return Number.isFinite(numeric) ? numeric : null;
    };
    const parseOptionalInt = (value) => {
        const numeric = parseOptionalNumber(value);
        return numeric === null ? null : Math.trunc(numeric);
    };

    const attackConfidenceGte = parseOptionalNumber(filters.attack_confidence_gte);
    const attackConfidenceLte = parseOptionalNumber(filters.attack_confidence_lte);
    const detectionConfidenceGte = parseOptionalNumber(filters.detection_confidence_gte);
    const detectionConfidenceLte = parseOptionalNumber(filters.detection_confidence_lte);
    const eventCountGte = parseOptionalInt(filters.event_count_gte);
    const eventCountLte = parseOptionalInt(filters.event_count_lte);
    const bytesGte = parseOptionalInt(filters.bytes_gte);
    const bytesLte = parseOptionalInt(filters.bytes_lte);
    const packetsGte = parseOptionalInt(filters.packets_gte);
    const packetsLte = parseOptionalInt(filters.packets_lte);

    const validateConfidenceRange = (name, minimum, maximum) => {
        if (minimum !== null && (minimum < 0 || minimum > 1)) {
            throw new Error(`filters.${name}_gte must be in range [0,1]`);
        }
        if (maximum !== null && (maximum < 0 || maximum > 1)) {
            throw new Error(`filters.${name}_lte must be in range [0,1]`);
        }
        if (minimum !== null && maximum !== null && minimum > maximum) {
            throw new Error(`filters.${name}_gte must be <= filters.${name}_lte`);
        }
    };
    validateConfidenceRange("attack_confidence", attackConfidenceGte, attackConfidenceLte);
    validateConfidenceRange("detection_confidence", detectionConfidenceGte, detectionConfidenceLte);

    [
        ["event_count", eventCountGte, eventCountLte],
        ["bytes", bytesGte, bytesLte],
        ["packets", packetsGte, packetsLte],
    ].forEach(([name, minimum, maximum]) => {
        if (minimum !== null && maximum !== null && minimum > maximum) {
            throw new Error(`filters.${name}_gte must be <= filters.${name}_lte`);
        }
    });

    const fromTimestamp = parseThreatHuntingClientFilterTimestamp(filters.from_timestamp, "from_timestamp");
    const toTimestamp = parseThreatHuntingClientFilterTimestamp(filters.to_timestamp, "to_timestamp");
    if (fromTimestamp && toTimestamp && fromTimestamp > toTimestamp) {
        throw new Error("filters.from_timestamp must be <= filters.to_timestamp");
    }
    const textContains = String(filters.text_contains ?? "").trim();
    if (textContains.length > 128) {
        throw new Error("filters.text_contains must be <= 128 characters");
    }

    return {
        source_ips: new Set(sourceIps.map((value) => value.toLowerCase())),
        target_ips: new Set(targetIps.map((value) => value.toLowerCase())),
        severities: new Set(severities.map((value) => value.toLowerCase())),
        attack_primary_classes: new Set(attackPrimaryClasses.map((value) => value.toLowerCase())),
        certainty_levels: new Set(certaintyLevels),
        triage_states: new Set(triageStates),
        attack_confidence_gte: attackConfidenceGte,
        attack_confidence_lte: attackConfidenceLte,
        detection_confidence_gte: detectionConfidenceGte,
        detection_confidence_lte: detectionConfidenceLte,
        event_count_gte: eventCountGte,
        event_count_lte: eventCountLte,
        bytes_gte: bytesGte,
        bytes_lte: bytesLte,
        packets_gte: packetsGte,
        packets_lte: packetsLte,
        from_timestamp: fromTimestamp,
        to_timestamp: toTimestamp,
        text_contains: textContains.toLowerCase(),
    };
}

function areThreatHuntingClientFiltersActive(filters) {
    const safeFilters = asObject(filters);
    return Object.values(safeFilters).some((value) => {
        if (value instanceof Set) return value.size > 0;
        if (value instanceof Date) return Number.isFinite(value.getTime());
        if (Array.isArray(value)) return value.length > 0;
        if (typeof value === "string") return value.trim().length > 0;
        return value !== null && value !== undefined;
    });
}

function buildThreatHuntingClientRecord(incident) {
    const safeIncident = asObject(incident);
    const typing = resolveAttackTypingDisplay(safeIncident);
    const detail = asObject(safeIncident.attack_detail);
    const detailCertainty = asObject(detail.certainty);
    const packetSourceIp = String(safeIncident.source_ip ?? "").trim();
    const attackerAlias = String(safeIncident.attacker_ip ?? "").trim() || packetSourceIp;
    const certaintyLevel = normalizeCertaintyLevel(
        detailCertainty.level ?? typing.certaintyLevel ?? safeIncident.attack_certainty_level
    );
    const certaintyText = String(
        detailCertainty.text
        ?? detail.certainty_text
        ?? typing.certaintyText
        ?? safeIncident.attack_certainty_text
        ?? ""
    ).trim();
    const attackConfidence = confidenceRatio(
        detail.confidence
        ?? typing.attackConfidence
        ?? safeIncident.attack_confidence
        ?? safeIncident.classification_confidence
        ?? safeIncident.confidence
    );
    const detectionConfidence = confidenceRatio(
        safeIncident.detection_confidence
        ?? typing.detectionConfidence
        ?? safeIncident.confidence
    );
    const triage = resolveIncidentTriage(safeIncident);
    const normalizedDetail = {
        ...detail,
        summary: String(detail.summary ?? typing.summary ?? safeIncident.attack_summary ?? "").trim(),
        primary_class: String(detail.primary_class ?? typing.primaryClass ?? safeIncident.attack_primary_class ?? "").trim(),
        confidence: attackConfidence ?? 0,
        method: String(detail.method ?? detail.source ?? typing.method ?? safeIncident.attack_method ?? "").trim(),
        source: String(detail.source ?? detail.method ?? typing.source ?? safeIncident.attack_method ?? "").trim(),
        certainty: {
            level: certaintyLevel,
            text: certaintyText,
        },
    };
    return {
        ...safeIncident,
        packet_source_ip: packetSourceIp,
        source_ip: attackerAlias,
        attacker_ip: attackerAlias,
        attack_summary: normalizedDetail.summary || String(typing.summary ?? "").trim(),
        attack_primary_class: normalizedDetail.primary_class || String(typing.primaryClass ?? "").trim(),
        attack_confidence: attackConfidence ?? 0,
        attack_certainty_level: certaintyLevel,
        attack_method: normalizedDetail.method || normalizedDetail.source,
        detection_confidence: detectionConfidence ?? 0,
        triage_state: triage.state,
        event_count: Number.isFinite(Number(safeIncident.event_count)) ? Math.trunc(Number(safeIncident.event_count)) : 0,
        bytes: Number.isFinite(Number(safeIncident.bytes)) ? Math.trunc(Number(safeIncident.bytes)) : 0,
        packets: Number.isFinite(Number(safeIncident.packets)) ? Math.trunc(Number(safeIncident.packets)) : 0,
        attack_detail: normalizedDetail,
    };
}

function incidentMatchesThreatHuntingClientFilters(record, filters) {
    const safeRecord = asObject(record);
    const safeFilters = asObject(filters);
    const sourceIp = String(safeRecord.source_ip ?? "").trim().toLowerCase();
    const targetIp = String(safeRecord.target_ip ?? "").trim().toLowerCase();
    const severity = String(safeRecord.severity ?? "").trim().toLowerCase();
    const attackPrimaryClass = String(
        safeRecord.attack_primary_class ?? asObject(safeRecord.attack_detail).primary_class ?? ""
    ).trim().toLowerCase();
    const certaintyLevel = normalizeCertaintyLevel(
        safeRecord.attack_certainty_level ?? asObject(asObject(safeRecord.attack_detail).certainty).level
    );
    const triageState = normalizeTriageState(safeRecord.triage_state);

    if (safeFilters.source_ips instanceof Set && safeFilters.source_ips.size && !safeFilters.source_ips.has(sourceIp)) {
        return false;
    }
    if (safeFilters.target_ips instanceof Set && safeFilters.target_ips.size && !safeFilters.target_ips.has(targetIp)) {
        return false;
    }
    if (safeFilters.severities instanceof Set && safeFilters.severities.size && !safeFilters.severities.has(severity)) {
        return false;
    }
    if (
        safeFilters.attack_primary_classes instanceof Set
        && safeFilters.attack_primary_classes.size
        && !safeFilters.attack_primary_classes.has(attackPrimaryClass)
    ) {
        return false;
    }
    if (
        safeFilters.certainty_levels instanceof Set
        && safeFilters.certainty_levels.size
        && !safeFilters.certainty_levels.has(certaintyLevel)
    ) {
        return false;
    }
    if (
        safeFilters.triage_states instanceof Set
        && safeFilters.triage_states.size
        && !safeFilters.triage_states.has(triageState)
    ) {
        return false;
    }

    const attackConfidence = confidenceRatio(safeRecord.attack_confidence) ?? 0;
    const detectionConfidence = confidenceRatio(safeRecord.detection_confidence) ?? 0;
    const eventCount = Number.isFinite(Number(safeRecord.event_count)) ? Math.trunc(Number(safeRecord.event_count)) : 0;
    const bytesValue = Number.isFinite(Number(safeRecord.bytes)) ? Math.trunc(Number(safeRecord.bytes)) : 0;
    const packets = Number.isFinite(Number(safeRecord.packets)) ? Math.trunc(Number(safeRecord.packets)) : 0;

    const gteChecks = [
        ["attack_confidence_gte", attackConfidence],
        ["detection_confidence_gte", detectionConfidence],
        ["event_count_gte", eventCount],
        ["bytes_gte", bytesValue],
        ["packets_gte", packets],
    ];
    for (const [field, candidate] of gteChecks) {
        const floor = safeFilters[field];
        if (floor !== null && floor !== undefined && candidate < floor) return false;
    }
    const lteChecks = [
        ["attack_confidence_lte", attackConfidence],
        ["detection_confidence_lte", detectionConfidence],
        ["event_count_lte", eventCount],
        ["bytes_lte", bytesValue],
        ["packets_lte", packets],
    ];
    for (const [field, candidate] of lteChecks) {
        const ceiling = safeFilters[field];
        if (ceiling !== null && ceiling !== undefined && candidate > ceiling) return false;
    }

    if (safeFilters.from_timestamp instanceof Date || safeFilters.to_timestamp instanceof Date) {
        const incidentDate = new Date(String(safeRecord.timestamp ?? "").trim());
        if (Number.isNaN(incidentDate.getTime())) return false;
        if (safeFilters.from_timestamp instanceof Date && incidentDate < safeFilters.from_timestamp) return false;
        if (safeFilters.to_timestamp instanceof Date && incidentDate > safeFilters.to_timestamp) return false;
    }

    const textContains = String(safeFilters.text_contains ?? "").trim().toLowerCase();
    if (textContains) {
        const detail = asObject(safeRecord.attack_detail);
        const certainty = asObject(detail.certainty);
        const searchableText = [
            safeRecord.id,
            safeRecord.source_ip,
            safeRecord.packet_source_ip,
            safeRecord.target_ip,
            safeRecord.severity,
            detail.summary,
            detail.primary_class,
            detail.description,
            certainty.text,
        ].map((part) => String(part ?? "").trim()).join(" ").toLowerCase();
        if (!searchableText.includes(textContains)) return false;
    }
    return true;
}

function tokenizeThreatHuntingDsl(query) {
    const tokens = [];
    const source = String(query ?? "");
    let index = 0;
    const isWordChar = (ch) => /[A-Za-z0-9_.-]/.test(ch);
    const keywords = new Set(["and", "or", "not", "in", "contains", "startswith", "true", "false", "null"]);

    const readString = (quote, start) => {
        let cursor = start + 1;
        let escaped = false;
        const chars = [];
        while (cursor < source.length) {
            const ch = source[cursor];
            if (escaped) {
                if (ch === "n") chars.push("\n");
                else if (ch === "t") chars.push("\t");
                else chars.push(ch);
                escaped = false;
                cursor += 1;
                continue;
            }
            if (ch === "\\") {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (ch === quote) {
                return { text: chars.join(""), nextIndex: cursor + 1 };
            }
            chars.push(ch);
            cursor += 1;
        }
        throw new Error(`Client DSL error at ${start}: Unterminated string literal`);
    };

    const readNumber = (start) => {
        let cursor = start;
        if (source[cursor] === "-") cursor += 1;
        let hasDigits = false;
        let hasDot = false;
        while (cursor < source.length) {
            const ch = source[cursor];
            if (/\d/.test(ch)) {
                hasDigits = true;
                cursor += 1;
                continue;
            }
            if (ch === "." && !hasDot) {
                hasDot = true;
                cursor += 1;
                continue;
            }
            break;
        }
        if (!hasDigits) {
            throw new Error(`Client DSL error at ${start}: Invalid numeric literal`);
        }
        return { text: source.slice(start, cursor), nextIndex: cursor };
    };

    while (index < source.length) {
        const ch = source[index];
        if (/\s/.test(ch)) {
            index += 1;
            continue;
        }
        if (ch === "(" || ch === ")" || ch === ",") {
            tokens.push({ kind: ch === "(" ? "LPAREN" : (ch === ")" ? "RPAREN" : "COMMA"), text: ch, position: index });
            index += 1;
            continue;
        }
        if (ch === "'" || ch === "\"") {
            const parsed = readString(ch, index);
            tokens.push({ kind: "STRING", text: parsed.text, position: index });
            index = parsed.nextIndex;
            continue;
        }
        if (/\d/.test(ch) || (ch === "-" && index + 1 < source.length && /\d/.test(source[index + 1]))) {
            const parsed = readNumber(index);
            tokens.push({ kind: "NUMBER", text: parsed.text, position: index });
            index = parsed.nextIndex;
            continue;
        }
        if ("=!<>".includes(ch)) {
            let op = "";
            if (index + 1 < source.length && source[index + 1] === "=") {
                op = source.slice(index, index + 2);
                index += 2;
            } else if (ch === ">" || ch === "<") {
                op = ch;
                index += 1;
            } else {
                throw new Error(`Client DSL error at ${index}: Unsupported operator`);
            }
            tokens.push({ kind: "OP", text: op, position: index - op.length });
            continue;
        }
        if (/[A-Za-z_]/.test(ch)) {
            const start = index;
            index += 1;
            while (index < source.length && isWordChar(source[index])) index += 1;
            const text = source.slice(start, index);
            const lower = text.toLowerCase();
            if (keywords.has(lower)) {
                tokens.push({ kind: "KEYWORD", text: lower, position: start });
            } else {
                tokens.push({ kind: "IDENT", text, position: start });
            }
            continue;
        }
        throw new Error(`Client DSL error at ${index}: Unexpected character '${ch}'`);
    }
    tokens.push({ kind: "EOF", text: "", position: source.length });
    return tokens;
}

function compileThreatHuntingDslQuery(query) {
    const normalizedQuery = String(query ?? "").trim();
    if (!normalizedQuery) return null;
    const tokens = tokenizeThreatHuntingDsl(normalizedQuery);
    let cursor = 0;

    const peek = () => tokens[cursor];
    const consume = () => {
        const token = tokens[cursor];
        cursor += 1;
        return token;
    };
    const match = (kind, text = null) => {
        const token = peek();
        if (!token || token.kind !== kind) return false;
        if (text !== null && token.text !== text) return false;
        consume();
        return true;
    };
    const expect = (kind, text, message) => {
        const token = peek();
        if (!token || token.kind !== kind || (text !== null && token.text !== text)) {
            throw new Error(`Client DSL error at ${token?.position ?? -1}: ${message}`);
        }
        return consume();
    };

    const parseLiteralValue = () => {
        const token = peek();
        if (!token) throw new Error("Client DSL error: unexpected end of input");
        if (token.kind === "NUMBER") {
            consume();
            return Number(token.text);
        }
        if (token.kind === "STRING") {
            consume();
            return token.text;
        }
        if (token.kind === "IDENT") {
            consume();
            return token.text;
        }
        if (token.kind === "KEYWORD") {
            consume();
            if (token.text === "true") return true;
            if (token.text === "false") return false;
            if (token.text === "null") return null;
        }
        throw new Error(`Client DSL error at ${token.position}: Expected literal value`);
    };

    const parseCollection = () => {
        const opener = peek();
        expect("LPAREN", null, "Expected tuple/list literal");
        const items = [];
        if (match("RPAREN")) return { kind: "literal", value: items };
        while (true) {
            items.push(parseLiteralValue());
            if (match("COMMA")) continue;
            expect("RPAREN", null, "Expected list closing parenthesis");
            break;
        }
        return { kind: "literal", value: items };
    };

    const parsePrimary = (fieldContext) => {
        const token = peek();
        if (!token) throw new Error("Client DSL error: unexpected end of input");
        if (match("LPAREN")) {
            const expr = parseOr();
            expect("RPAREN", null, "Expected closing parenthesis");
            return expr;
        }
        if (token.kind === "IDENT") {
            const ident = consume().text;
            return fieldContext ? { kind: "field", name: ident } : { kind: "literal", value: ident };
        }
        if (token.kind === "NUMBER" || token.kind === "STRING" || (token.kind === "KEYWORD" && ["true", "false", "null"].includes(token.text))) {
            return { kind: "literal", value: parseLiteralValue() };
        }
        throw new Error(`Client DSL error at ${token.position}: Unexpected token`);
    };

    const parsePredicate = () => {
        const left = parsePrimary(true);
        const token = peek();
        if (token.kind === "OP") {
            const operator = consume().text;
            const right = parsePrimary(false);
            const opMap = {
                "==": "eq",
                "!=": "ne",
                ">": "gt",
                ">=": "gte",
                "<": "lt",
                "<=": "lte",
            };
            return { kind: "compare", op: opMap[operator], left, right };
        }
        if (token.kind === "KEYWORD") {
            if (match("KEYWORD", "in")) {
                return { kind: "compare", op: "in", left, right: parseCollection() };
            }
            if (match("KEYWORD", "contains")) {
                return { kind: "compare", op: "contains", left, right: parsePrimary(false) };
            }
            if (match("KEYWORD", "startswith")) {
                return { kind: "compare", op: "startswith", left, right: parsePrimary(false) };
            }
        }
        return left;
    };

    const parseNot = () => {
        if (match("KEYWORD", "not")) {
            return { kind: "unary", op: "not", operand: parseNot() };
        }
        return parsePredicate();
    };

    const parseAnd = () => {
        let node = parseNot();
        while (match("KEYWORD", "and")) {
            node = { kind: "logical", op: "and", left: node, right: parseNot() };
        }
        return node;
    };

    const parseOr = () => {
        let node = parseAnd();
        while (match("KEYWORD", "or")) {
            node = { kind: "logical", op: "or", left: node, right: parseAnd() };
        }
        return node;
    };

    const ast = parseOr();
    if (peek().kind !== "EOF") {
        throw new Error(`Client DSL error at ${peek().position}: Unexpected trailing token`);
    }

    const toNumber = (value) => {
        const numeric = Number(value);
        return Number.isFinite(numeric) ? numeric : null;
    };
    const safeLower = (value) => String(value ?? "").trim().toLowerCase();
    const compareEq = (left, right) => {
        const leftNum = toNumber(left);
        const rightNum = toNumber(right);
        if (leftNum !== null && rightNum !== null) return leftNum === rightNum;
        return safeLower(left) === safeLower(right);
    };
    const compareOrdered = (left, right, op) => {
        const leftNum = toNumber(left);
        const rightNum = toNumber(right);
        if (leftNum !== null && rightNum !== null) {
            if (op === "gt") return leftNum > rightNum;
            if (op === "gte") return leftNum >= rightNum;
            if (op === "lt") return leftNum < rightNum;
            return leftNum <= rightNum;
        }
        const leftText = safeLower(left);
        const rightText = safeLower(right);
        if (op === "gt") return leftText > rightText;
        if (op === "gte") return leftText >= rightText;
        if (op === "lt") return leftText < rightText;
        return leftText <= rightText;
    };
    const truthy = (value) => (typeof value === "string" ? value.trim().length > 0 : !!value);
    const resolveField = (record, fieldPath) => {
        if (!record || typeof record !== "object") return undefined;
        if (Object.prototype.hasOwnProperty.call(record, fieldPath)) {
            return record[fieldPath];
        }
        let cursorValue = record;
        for (const segment of String(fieldPath).split(".")) {
            if (!cursorValue || typeof cursorValue !== "object" || !(segment in cursorValue)) {
                return undefined;
            }
            cursorValue = cursorValue[segment];
        }
        return cursorValue;
    };

    const evalNode = (node, record) => {
        if (!node || typeof node !== "object") return false;
        if (node.kind === "literal") return node.value;
        if (node.kind === "field") return resolveField(record, node.name);
        if (node.kind === "unary") {
            if (node.op === "not") return !truthy(evalNode(node.operand, record));
            throw new Error(`Client DSL error: Unsupported unary operator '${node.op}'`);
        }
        if (node.kind === "logical") {
            if (node.op === "and") {
                const left = truthy(evalNode(node.left, record));
                if (!left) return false;
                return truthy(evalNode(node.right, record));
            }
            if (node.op === "or") {
                const left = truthy(evalNode(node.left, record));
                if (left) return true;
                return truthy(evalNode(node.right, record));
            }
            throw new Error(`Client DSL error: Unsupported logical operator '${node.op}'`);
        }
        if (node.kind === "compare") {
            const left = evalNode(node.left, record);
            if (node.op === "eq") return compareEq(left, evalNode(node.right, record));
            if (node.op === "ne") return !compareEq(left, evalNode(node.right, record));
            if (["gt", "gte", "lt", "lte"].includes(node.op)) {
                return compareOrdered(left, evalNode(node.right, record), node.op);
            }
            if (node.op === "in") {
                const right = evalNode(node.right, record);
                const values = Array.isArray(right) ? right : [right];
                return values.some((value) => compareEq(left, value));
            }
            if (node.op === "contains") {
                const right = evalNode(node.right, record);
                if (typeof left === "string") return safeLower(left).includes(safeLower(right));
                if (Array.isArray(left)) return left.some((value) => compareEq(value, right));
                if (left && typeof left === "object") {
                    return Object.keys(left).some((key) => compareEq(key, right));
                }
                return false;
            }
            if (node.op === "startswith") {
                return safeLower(left).startsWith(safeLower(evalNode(node.right, record)));
            }
            throw new Error(`Client DSL error: Unsupported comparison operator '${node.op}'`);
        }
        throw new Error("Client DSL error: Invalid query expression");
    };

    return (record) => truthy(evalNode(ast, record));
}

function buildThreatHuntingClientFallbackScientificMethods(payload, filteredIncidents) {
    const safePayload = asObject(payload);
    const filtered = asArray(filteredIncidents);
    const scientificMethodsCfg = asObject(safePayload.scientific_methods);
    const enabledMethods = asArray(scientificMethodsCfg.enabled)
        .map((method) => String(method ?? "").trim())
        .filter(Boolean);
    const effectiveEnabledMethods = enabledMethods.length ? enabledMethods : HUNTING_DEFAULT_SCIENTIFIC_METHODS;
    const maxIncidentsRaw = Number(scientificMethodsCfg.max_incidents);
    const maxIncidents = Number.isFinite(maxIncidentsRaw) && maxIncidentsRaw > 0
        ? Math.trunc(maxIncidentsRaw)
        : 800;
    const analyzedIncidents = Math.min(filtered.length, Math.max(0, maxIncidents));
    return {
        z_score_outliers: { outliers: [] },
        temporal_bursts: { bursts: [] },
        entropy_indicators: { indicators: [] },
        clustering_lite: { clusters: [] },
        meta: {
            input_incidents: filtered.length,
            analyzed_incidents: analyzedIncidents,
            enabled_methods: effectiveEnabledMethods,
            execution_mode: "client-fallback",
            note: "Scientific-method engines are unavailable in client fallback mode.",
        },
    };
}

async function executeThreatHuntingClientFallbackQuery(payload, context = {}) {
    const safePayload = asObject(payload);
    const { maxScan, maxLimit } = getThreatHuntingClientFallbackCaps();
    const requestedLimit = Number(safePayload.limit);
    const limit = Number.isFinite(requestedLimit)
        ? Math.max(1, Math.min(Math.trunc(requestedLimit), maxLimit))
        : Math.min(100, maxLimit);
    const requestedOffset = Number(safePayload.offset);
    const offset = Number.isFinite(requestedOffset)
        ? Math.max(0, Math.min(Math.trunc(requestedOffset), maxScan))
        : 0;
    const requestedScan = Number(safePayload.scan_limit);
    const scanSeed = Number.isFinite(requestedScan) && requestedScan > 0
        ? Math.trunc(requestedScan)
        : Math.max(600, limit + offset);
    const scanLimit = Math.max(1, Math.min(Math.max(scanSeed, limit + offset), maxScan));
    const incidentsPayload = asObject(await fetchJson(`/api/incidents?limit=${scanLimit}`));
    const incidents = asArray(incidentsPayload.items)
        .filter((item) => item && typeof item === "object")
        .map((item) => buildThreatHuntingClientRecord(item));
    const normalizedFilters = normalizeThreatHuntingClientFilters(safePayload.filters);
    let filteredIncidents = incidents.filter((incident) => incidentMatchesThreatHuntingClientFilters(incident, normalizedFilters));
    const dslQuery = String(safePayload.dsl ?? safePayload.query ?? "").trim();
    const dslEvaluator = dslQuery ? compileThreatHuntingDslQuery(dslQuery) : null;
    if (dslEvaluator) {
        filteredIncidents = filteredIncidents.filter((incident) => dslEvaluator(incident));
    }
    const totalMatches = filteredIncidents.length;
    const items = filteredIncidents.slice(offset, offset + limit);
    const scientificMethods = buildThreatHuntingClientFallbackScientificMethods(safePayload, filteredIncidents);
    const attemptedModes = asArray(context.attemptedModes)
        .map((mode) => String(mode ?? "").trim())
        .filter(Boolean);
    return {
        queryResult: {
            items,
            total_matches: totalMatches,
            query: {
                dsl: dslQuery,
                limit,
                offset,
                scan_limit: scanLimit,
                structured_filters_applied: areThreatHuntingClientFiltersActive(normalizedFilters),
                dsl_applied: !!dslEvaluator,
            },
            scientific_methods: scientificMethods,
            meta: {
                source: "hunting-query-client-fallback",
                staged: false,
                client_side_fallback: true,
                fallback_reason: "backend-query-unavailable-or-incompatible",
                attempted_modes: attemptedModes,
                last_compatibility_issue: String(context.failureMessage ?? "").trim(),
                base_incident_count: incidents.length,
                post_filter_incident_count: totalMatches,
                page_size: items.length,
                certainty_levels: ["not_sure", "probable", "certain"],
            },
        },
        executionMode: "CLIENT /api/incidents fallback",
        fallbackType: "client-side",
    };
}

async function executeThreatHuntingQueryWithFallback(payload) {
    const params = buildThreatHuntingQueryParams(payload);
    const jsonHeaders = { "Content-Type": "application/json" };
    const payloadWithAction = { ...asObject(payload), action: "query" };
    const attempts = [
        {
            mode: "POST /api/hunting/query",
            run: () => fetchJson("/api/hunting/query", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payload),
            }),
        },
        {
            mode: "GET /api/hunting/query",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/hunting/query", params)),
        },
        {
            mode: "POST /api/threat-hunting/query",
            run: () => fetchJson("/api/threat-hunting/query", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payload),
            }),
        },
        {
            mode: "GET /api/threat-hunting/query",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/threat-hunting/query", params)),
        },
        {
            mode: "POST /api/hunting/search",
            run: () => fetchJson("/api/hunting/search", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payload),
            }),
        },
        {
            mode: "GET /api/hunting/search",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/hunting/search", params)),
        },
        {
            mode: "POST /api/threat-hunting/search",
            run: () => fetchJson("/api/threat-hunting/search", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payload),
            }),
        },
        {
            mode: "GET /api/threat-hunting/search",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/threat-hunting/search", params)),
        },
        {
            mode: "POST /api/hunting/execute",
            run: () => fetchJson("/api/hunting/execute", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payload),
            }),
        },
        {
            mode: "GET /api/hunting/execute",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/hunting/execute", params)),
        },
        {
            mode: "POST /api/threat-hunting/execute",
            run: () => fetchJson("/api/threat-hunting/execute", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payload),
            }),
        },
        {
            mode: "GET /api/threat-hunting/execute",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/threat-hunting/execute", params)),
        },
        {
            mode: "POST /api/hunting?action=query",
            run: () => fetchJson("/api/hunting?action=query", {
                method: "POST",
                headers: jsonHeaders,
                body: JSON.stringify(payloadWithAction),
            }),
        },
        {
            mode: "GET /api/hunting?action=query",
            run: () => fetchJson(buildThreatHuntingEndpointUrl("/api/hunting", params, { action: "query" })),
        },
    ];
    const attemptedModes = [];
    let lastCompatibilityError = null;
    for (const attempt of attempts) {
        attemptedModes.push(attempt.mode);
        try {
            const result = asObject(await attempt.run());
            if (!isThreatHuntingQueryResponse(result)) {
                const shapeError = new Error(`Incompatible response payload from ${attempt.mode}.`);
                shapeError.compatibility = true;
                throw shapeError;
            }
            return {
                queryResult: result,
                executionMode: attempt.mode,
                fallbackType: attempt.mode === "POST /api/hunting/query" ? "none" : "backend-compatibility",
            };
        } catch (error) {
            if (error?.compatibility || isThreatHuntingCompatibilityIssue(error)) {
                lastCompatibilityError = error;
                continue;
            }
            throw error;
        }
    }
    const attemptedSummary = attemptedModes.join(", ");
    const failureMessage = String(lastCompatibilityError?.message ?? "No compatible endpoint accepted the query.");
    try {
        return await executeThreatHuntingClientFallbackQuery(payload, {
            attemptedModes,
            failureMessage,
        });
    } catch (fallbackError) {
        const fallbackMessage = String(fallbackError?.message ?? "Unknown client fallback error");
        throw new Error(
            `Threat hunting query unavailable after compatibility retries. Attempted modes: ${attemptedSummary}. Last compatibility issue: ${failureMessage}. Client-side fallback failed: ${fallbackMessage}`
        );
    }
}

function renderThreatHuntingScientificMethodOptions(capabilities) {
    const container = document.getElementById("huntingScientificMethods");
    if (!container) return;
    const scientificMethods = asObject(asObject(capabilities).scientific_methods);
    const available = asArray(scientificMethods.available)
        .map((method) => String(method ?? "").trim())
        .filter(Boolean);
    const methods = available.length ? available : HUNTING_DEFAULT_SCIENTIFIC_METHODS;
    const currentSelection = state.hunting.selectedScientificMethods.length
        ? state.hunting.selectedScientificMethods
        : getSelectedScientificMethods();
    const selected = new Set(currentSelection.length ? currentSelection : methods);
    container.innerHTML = methods.map((method) => `
        <label class="hunting-check-option">
            <input type="checkbox" name="huntingScientificMethod" value="${escapeHtml(method)}"${selected.has(method) ? " checked" : ""}>
            <span>${escapeHtml(formatHuntingMethodLabel(method))}</span>
        </label>
    `).join("");
    state.hunting.selectedScientificMethods = methods.filter((method) => selected.has(method));
}

function updateThreatHuntingMetaIndicators(payload) {
    const entries = [];
    const safePayload = asObject(payload);
    const capabilities = asObject(state.hunting.capabilities);
    const queryResult = asObject(state.hunting.queryResult);
    if (Object.keys(asObject(safePayload.meta)).length) {
        entries.push({ label: "Hunting", meta: safePayload.meta });
    }
    if (Object.keys(asObject(capabilities.meta)).length) {
        entries.push({ label: "Capabilities", meta: capabilities.meta });
    }
    if (Object.keys(asObject(queryResult.meta)).length) {
        entries.push({ label: "Query", meta: queryResult.meta });
    }
    setViewMetaIndicators("threat-hunting", entries);
}

function initializeThreatHuntingWorkspace(payload) {
    if (state.hunting.initialized) return;
    setMultiSelectOptions("huntingFilterSeverities", HUNTING_DEFAULT_SEVERITIES);
    setMultiSelectOptions("huntingFilterCertaintyLevels", HUNTING_DEFAULT_CERTAINTY_LEVELS);
    setMultiSelectOptions("huntingFilterTriageStates", HUNTING_DEFAULT_TRIAGE_STATES);
    const limitInput = document.getElementById("huntingFilterLimit");
    const offsetInput = document.getElementById("huntingFilterOffset");
    const scanInput = document.getElementById("huntingFilterScanLimit");
    const maxIncidentsInput = document.getElementById("huntingScientificMaxIncidents");
    if (limitInput && !String(limitInput.value ?? "").trim()) limitInput.value = "100";
    if (offsetInput && !String(offsetInput.value ?? "").trim()) offsetInput.value = "0";
    if (scanInput && !String(scanInput.value ?? "").trim()) scanInput.value = "600";
    if (maxIncidentsInput && !String(maxIncidentsInput.value ?? "").trim()) maxIncidentsInput.value = "800";
    renderThreatHuntingScientificMethodOptions(state.hunting.capabilities);
    state.hunting.initialized = true;
}

function renderThreatHuntingWorkspace(payload) {
    const safePayload = asObject(payload);
    const capabilities = asObject(state.hunting.capabilities);
    const summary = document.getElementById("huntingCapabilitiesSummary");
    const dsl = asObject(capabilities.dsl);
    const meta = asObject(capabilities.meta);
    const guardrails = Object.keys(asObject(meta.query_guardrails)).length
        ? asObject(meta.query_guardrails)
        : asObject(meta.guardrails);
    const defaultMethodLimit = Number(asObject(capabilities.scientific_methods).default_max_incidents || 800);
    const maxIncidentsInput = document.getElementById("huntingScientificMaxIncidents");
    if (maxIncidentsInput && !String(maxIncidentsInput.value ?? "").trim()) {
        maxIncidentsInput.value = String(defaultMethodLimit > 0 ? defaultMethodLimit : 800);
    }
    if (summary) {
        const fieldsCount = asArray(dsl.field_allowlist).length;
        const operatorsCount = asArray(dsl.operators).length;
        const maxLength = Number(dsl.max_query_length || 0);
        const maxTokens = Number(dsl.max_tokens || 0);
        const maxDepth = Number(dsl.max_depth || 0);
        const maxResultLimit = Number(guardrails.max_result_limit || 0);
        const maxScanIncidents = Number(guardrails.max_scan_incidents || 0);
        const parts = [
            `${fmtNumber(fieldsCount)} DSL fields`,
            `${fmtNumber(operatorsCount)} operators`,
            maxLength > 0 ? `max query length ${fmtNumber(maxLength)}` : "",
            maxTokens > 0 ? `max tokens ${fmtNumber(maxTokens)}` : "",
            maxDepth > 0 ? `max depth ${fmtNumber(maxDepth)}` : "",
            maxResultLimit > 0 ? `result cap ${fmtNumber(maxResultLimit)}` : "",
            maxScanIncidents > 0 ? `scan cap ${fmtNumber(maxScanIncidents)}` : "",
        ].filter(Boolean);
        summary.textContent = parts.join(" · ") || "Capabilities unavailable. You can still run broad queries.";
    }
    renderThreatHuntingScientificMethodOptions(capabilities);
    renderThreatHuntingQueryResults();
}

function getThreatHuntingQueryRowsForDisplay() {
    const result = asObject(state.hunting.queryResult);
    const allRows = asArray(result.items).filter((item) => item && typeof item === "object");
    const searchTerm = getSearchTerm();
    const visibleRows = filterBySearch(allRows, searchTerm);
    return { result, allRows, visibleRows, searchTerm };
}

function renderThreatHuntingQueryCharts(rows) {
    const safeRows = asArray(rows).filter((item) => item && typeof item === "object");
    const severityCounter = {};
    const certaintyCounter = { not_sure: 0, probable: 0, certain: 0 };
    const sourceCounter = {};
    safeRows.forEach((item) => {
        const safeItem = asObject(item);
        const severity = String(safeItem.severity ?? "LOW").trim().toUpperCase() || "LOW";
        const typing = resolveAttackTypingDisplay(safeItem);
        const certainty = normalizeCertaintyLevel(typing.certaintyLevel);
        const source = String(safeItem.attacker_ip ?? safeItem.source_ip ?? "--").trim() || "--";
        severityCounter[severity] = (severityCounter[severity] || 0) + 1;
        certaintyCounter[certainty] = (certaintyCounter[certainty] || 0) + 1;
        sourceCounter[source] = (sourceCounter[source] || 0) + 1;
    });
    const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const severityLabels = severityOrder.filter((label) => severityCounter[label] > 0);
    const effectiveSeverityLabels = severityLabels.length ? severityLabels : ["No matches"];
    const severityValues = severityLabels.length ? severityLabels.map((label) => severityCounter[label]) : [0];
    const severityColors = {
        CRITICAL: "#dc2626",
        HIGH: "#ef4444",
        MEDIUM: "#f59e0b",
        LOW: "#3b82f6",
    };
    huntingSeverityChart = upsertThreatIntelChart(
        "huntingSeverity",
        huntingSeverityChart,
        "huntingSeverityChart",
        "bar",
        {
            labels: effectiveSeverityLabels,
            datasets: [{
                label: "Incidents",
                data: severityValues,
                backgroundColor: effectiveSeverityLabels.map((label) => severityColors[label] || "#64748b"),
            }],
        },
        { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    );

    const certaintyOrder = ["certain", "probable", "not_sure"];
    const certaintyLabels = certaintyOrder.filter((label) => certaintyCounter[label] > 0);
    const effectiveCertaintyLabels = certaintyLabels.length ? certaintyLabels.map((label) => certaintyLevelLabel(label)) : ["No matches"];
    const certaintyValues = certaintyLabels.length ? certaintyLabels.map((label) => certaintyCounter[label]) : [1];
    const certaintyColors = certaintyLabels.length
        ? certaintyLabels.map((label) => {
            if (label === "certain") return "#10b981";
            if (label === "probable") return "#3b82f6";
            return "#f59e0b";
        })
        : ["#374151"];
    huntingCertaintyChart = upsertThreatIntelChart(
        "huntingCertainty",
        huntingCertaintyChart,
        "huntingCertaintyChart",
        "doughnut",
        {
            labels: effectiveCertaintyLabels,
            datasets: [{ data: certaintyValues, backgroundColor: certaintyColors }],
        },
        { plugins: { legend: { position: "bottom" } } }
    );

    const topSources = Object.entries(sourceCounter)
        .map(([source, count]) => ({ source, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);
    const sourceLabels = topSources.length ? topSources.map((entry) => entry.source) : ["No matches"];
    const sourceValues = topSources.length ? topSources.map((entry) => entry.count) : [0];
    huntingTopSourcesChart = upsertThreatIntelChart(
        "huntingTopSources",
        huntingTopSourcesChart,
        "huntingTopSourcesChart",
        "bar",
        {
            labels: sourceLabels,
            datasets: [{ label: "Incidents", data: sourceValues, backgroundColor: "#8b5cf6" }],
        },
        {
            indexAxis: "y",
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
        }
    );
}

function renderThreatHuntingScientificSummary(queryResult) {
    const summary = document.getElementById("huntingScientificSummary");
    const signals = document.getElementById("huntingScientificSignals");
    if (!summary || !signals) return;
    if (!queryResult || typeof queryResult !== "object") {
        summary.textContent = "Run a query to evaluate scientific-method heuristics.";
        signals.innerHTML = '<li class="list-empty">No scientific signals yet.</li>';
        return;
    }
    const scientific = asObject(asObject(queryResult).scientific_methods);
    const meta = asObject(scientific.meta);
    const analyzedIncidents = toSafeCount(meta.analyzed_incidents);
    const inputIncidents = toSafeCount(meta.input_incidents);
    const enabledMethods = asArray(meta.enabled_methods).map((name) => formatHuntingMethodLabel(name));
    summary.textContent = `Analyzed ${fmtNumber(analyzedIncidents)} incidents (${fmtNumber(inputIncidents)} candidate incidents) using ${enabledMethods.join(", ") || "no methods"}.`;
    const signalRows = [];
    const zOutliers = asArray(asObject(scientific.z_score_outliers).outliers).length;
    const bursts = asArray(asObject(scientific.temporal_bursts).bursts).length;
    const entropyIndicators = asArray(asObject(scientific.entropy_indicators).indicators);
    const clusters = asArray(asObject(scientific.clustering_lite).clusters).length;
    if (zOutliers > 0) signalRows.push(`${fmtNumber(zOutliers)} z-score outliers identified.`);
    if (bursts > 0) signalRows.push(`${fmtNumber(bursts)} temporal burst windows identified.`);
    if (entropyIndicators.length) signalRows.push(`Entropy indicators: ${entropyIndicators.join(", ")}.`);
    if (clusters > 0) signalRows.push(`${fmtNumber(clusters)} cluster archetypes exceeded cluster-size threshold.`);
    signals.innerHTML = signalRows.length
        ? signalRows.map((text) => `<li>${escapeHtml(text)}</li>`).join("")
        : '<li class="list-empty">No elevated patterns flagged by the selected scientific methods.</li>';
}

function setThreatHuntingResultState(message, variant = "") {
    setStatusMessage("huntingQueryResultState", message, variant);
}

function scrollThreatHuntingResultsIntoView({ highlight = false } = {}) {
    const card = document.getElementById("huntingQueryResultsCard");
    if (!card) return;
    card.scrollIntoView({ behavior: "smooth", block: "start" });
    if (!highlight) return;
    card.classList.add("is-highlighted");
    if (state.hunting.resultsHighlightTimer) {
        clearTimeout(state.hunting.resultsHighlightTimer);
    }
    state.hunting.resultsHighlightTimer = setTimeout(() => {
        card.classList.remove("is-highlighted");
        state.hunting.resultsHighlightTimer = null;
    }, 1500);
}

function renderThreatHuntingQueryPendingState() {
    const body = document.getElementById("huntingQueryRows");
    const summary = document.getElementById("huntingQueryResultSummary");
    if (!body || !summary) return;
    if (state.hunting.queryResult) {
        summary.textContent = "Executing query... keeping previous results visible until refresh.";
        return;
    }
    summary.textContent = "Executing query...";
    body.innerHTML = "<tr><td colspan=\"9\">Executing query... results will appear in this panel.</td></tr>";
    renderThreatHuntingQueryCharts([]);
    renderThreatHuntingScientificSummary(null);
}

function renderThreatHuntingQueryErrorState(message) {
    const body = document.getElementById("huntingQueryRows");
    const summary = document.getElementById("huntingQueryResultSummary");
    if (!body || !summary) return;
    if (state.hunting.queryResult) {
        summary.textContent = "Latest query failed. Showing previous successful results.";
        return;
    }
    summary.textContent = "Query failed before results were returned.";
    body.innerHTML = `<tr><td colspan="9">${escapeHtml(message)}</td></tr>`;
    renderThreatHuntingQueryCharts([]);
    renderThreatHuntingScientificSummary(null);
}

function renderThreatHuntingQueryResults() {
    const body = document.getElementById("huntingQueryRows");
    const summary = document.getElementById("huntingQueryResultSummary");
    if (!body || !summary) return;
    const hasQueryResult = !!state.hunting.queryResult;
    if (!hasQueryResult) {
        summary.textContent = "Run a query to inspect filtered hunting results and analytics.";
        body.innerHTML = "<tr><td colspan=\"9\">Run a query to populate the workspace.</td></tr>";
        setThreatHuntingResultState("Results appear here after you run a hunting query.", "pending");
        renderThreatHuntingQueryCharts([]);
        renderThreatHuntingScientificSummary(null);
        return;
    }
    const { result, allRows, visibleRows, searchTerm } = getThreatHuntingQueryRowsForDisplay();
    const hiddenBySearch = Math.max(0, allRows.length - visibleRows.length);
    const query = asObject(result.query);
    const totalMatches = Number.isFinite(Number(result.total_matches))
        ? toSafeCount(result.total_matches)
        : allRows.length;
    const scopeBits = [];
    if (query.structured_filters_applied) scopeBits.push("structured filters");
    if (query.dsl_applied) scopeBits.push("DSL");
    const scopeLabel = scopeBits.length ? scopeBits.join(" + ") : "no filters";
    const hiddenLabel = hiddenBySearch > 0 ? ` · ${fmtNumber(hiddenBySearch)} hidden by search` : "";
    summary.textContent = `${fmtNumber(visibleRows.length)} shown · ${fmtNumber(totalMatches)} total matches · ${scopeLabel}${hiddenLabel}`;
    if (!visibleRows.length) {
        const emptyMessage = allRows.length
            ? buildEmptyStateMessage("No query rows", searchTerm)
            : "No incidents matched the query.";
        body.innerHTML = `<tr><td colspan="9">${escapeHtml(emptyMessage)}</td></tr>`;
        setThreatHuntingResultState(
            allRows.length
                ? `Query returned ${fmtNumber(allRows.length)} row(s), but none are visible with the current search.`
                : "Query completed with no matching incidents.",
            "pending"
        );
        renderThreatHuntingQueryCharts([]);
        renderThreatHuntingScientificSummary(result);
        return;
    }
    body.innerHTML = visibleRows.map((item) => {
        const safeItem = asObject(item);
        const typing = resolveAttackTypingDisplay(safeItem);
        const incidentId = String(safeItem.id ?? "--");
        const timestamp = safeItem.timestamp ? String(safeItem.timestamp).slice(0, 19).replace("T", " ") : "--";
        const source = String(safeItem.attacker_ip ?? safeItem.source_ip ?? "--").trim() || "--";
        const targetIps = normalizeStringList(safeItem.target_ips);
        const targetIp = String(safeItem.target_ip ?? "").trim();
        if (targetIp && !targetIps.includes(targetIp)) targetIps.unshift(targetIp);
        const target = targetIps.length > 1 ? `${targetIps[0]} +${targetIps.length - 1}` : (targetIps[0] || "--");
        const severity = String(safeItem.severity || "LOW");
        const triage = resolveIncidentTriage(safeItem);
        return `<tr class="interactive hunting-query-row" data-incident-id="${escapeHtml(incidentId)}">
            <td class="mono">${escapeHtml(incidentId)}</td>
            <td class="mono">${escapeHtml(timestamp)}</td>
            <td class="mono">${escapeHtml(source)}</td>
            <td class="mono">${escapeHtml(target)}</td>
            <td>${escapeHtml(typing.primaryClass)}</td>
            <td><span class="tag ${severityTagClass(severity)}">${escapeHtml(severity)}</span></td>
            <td>${escapeHtml(fmtConfidence(typing.attackConfidence ?? typing.detectionConfidence, 2))}</td>
            <td>${escapeHtml(typing.certaintyLabel)}</td>
            <td>${escapeHtml(triage.label)}</td>
        </tr>`;
    }).join("");
    body.querySelectorAll(".hunting-query-row").forEach((row) => {
        row.addEventListener("click", () => {
            const incidentId = String(row.dataset.incidentId ?? "");
            const found = allRows.find((incident) => String(asObject(incident).id ?? "") === incidentId)
                || state.incidents.find((incident) => String(asObject(incident).id ?? "") === incidentId);
            if (found) openIncidentModal(found);
        });
    });
    setThreatHuntingResultState(
        hiddenBySearch > 0
            ? `Showing ${fmtNumber(visibleRows.length)} row(s). ${fmtNumber(hiddenBySearch)} row(s) hidden by global search.`
            : `Showing ${fmtNumber(visibleRows.length)} row(s). Click a row to inspect incident details.`,
        "success"
    );
    renderThreatHuntingQueryCharts(visibleRows);
    renderThreatHuntingScientificSummary(result);
}

async function executeThreatHuntingQuery() {
    setButtonLoadingState("huntingRunQuery", true, "Running...");
    setStatusMessage("huntingQueryStatus", "Executing hunting query...", "pending");
    setThreatHuntingResultState("Running query... results will refresh in the Query Results panel.", "pending");
    renderThreatHuntingQueryPendingState();
    try {
        const payload = buildThreatHuntingQueryPayload();
        state.hunting.lastQueryPayload = payload;
        const { queryResult, executionMode, fallbackType } = await executeThreatHuntingQueryWithFallback(payload);
        state.hunting.queryResult = queryResult;
        renderThreatHuntingQueryResults();
        const totalMatches = Number.isFinite(Number(queryResult.total_matches))
            ? toSafeCount(queryResult.total_matches)
            : asArray(queryResult.items).length;
        const shown = asArray(queryResult.items).length;
        const usedClientFallback = fallbackType === "client-side";
        const usedCompatibilityFallback = fallbackType === "backend-compatibility";
        const usedFallback = usedClientFallback || usedCompatibilityFallback;
        const completionPrefix = usedClientFallback
            ? "Query complete via client-side /api/incidents fallback"
            : (usedCompatibilityFallback ? `Query complete via ${executionMode}` : "Query complete");
        setStatusMessage(
            "huntingQueryStatus",
            `${completionPrefix}: ${fmtNumber(shown)} rows returned (${fmtNumber(totalMatches)} matches).`,
            "success"
        );
        const fallbackNote = usedClientFallback
            ? " Client-side fallback used /api/incidents after backend query endpoint compatibility retries failed."
            : (usedCompatibilityFallback ? ` Compatibility fallback executed (${executionMode}).` : "");
        setThreatHuntingResultState(
            shown > 0
                ? `Query updated ${fmtNumber(shown)} row(s). See the Query Results panel below.${fallbackNote}`
                : `Query completed with no direct rows. Review summary and adjust filters.${fallbackNote}`,
            shown > 0 ? "success" : "pending"
        );
        updateThreatHuntingMetaIndicators(state.cachedViewData.hunting);
        scrollThreatHuntingResultsIntoView({ highlight: true });
    } catch (error) {
        const message = String(error?.message ?? "Failed to execute hunting query");
        setStatusMessage("huntingQueryStatus", message, "error");
        setThreatHuntingResultState(`Query failed: ${message}`, "error");
        renderThreatHuntingQueryErrorState(message);
        scrollThreatHuntingResultsIntoView({ highlight: true });
    } finally {
        setButtonLoadingState("huntingRunQuery", false);
    }
}

function resetThreatHuntingQueryWorkspace() {
    [
        "huntingFilterSourceIps",
        "huntingFilterTargetIps",
        "huntingFilterAttackClasses",
        "huntingFilterTextContains",
        "huntingFilterAttackConfidenceGte",
        "huntingFilterAttackConfidenceLte",
        "huntingFilterDetectionConfidenceGte",
        "huntingFilterDetectionConfidenceLte",
        "huntingFilterEventCountGte",
        "huntingFilterEventCountLte",
        "huntingFilterBytesGte",
        "huntingFilterBytesLte",
        "huntingFilterPacketsGte",
        "huntingFilterPacketsLte",
        "huntingFilterFromTimestamp",
        "huntingFilterToTimestamp",
        "huntingDslInput",
    ].forEach((id) => {
        const input = document.getElementById(id);
        if (input) input.value = "";
    });
    const limitInput = document.getElementById("huntingFilterLimit");
    const offsetInput = document.getElementById("huntingFilterOffset");
    const scanInput = document.getElementById("huntingFilterScanLimit");
    if (limitInput) limitInput.value = "100";
    if (offsetInput) offsetInput.value = "0";
    if (scanInput) scanInput.value = "600";
    setMultiSelectOptions("huntingFilterSeverities", HUNTING_DEFAULT_SEVERITIES, { selectedValues: [] });
    setMultiSelectOptions("huntingFilterCertaintyLevels", HUNTING_DEFAULT_CERTAINTY_LEVELS, { selectedValues: [] });
    setMultiSelectOptions("huntingFilterTriageStates", HUNTING_DEFAULT_TRIAGE_STATES, { selectedValues: [] });
    state.hunting.selectedScientificMethods = [];
    renderThreatHuntingScientificMethodOptions(state.hunting.capabilities);
    state.hunting.queryResult = null;
    state.hunting.lastQueryPayload = null;
    renderThreatHuntingWorkspace(state.cachedViewData.hunting);
    updateThreatHuntingMetaIndicators(state.cachedViewData.hunting);
    setStatusMessage("huntingQueryStatus", "Hunting query workspace reset.", "success");
}

function renderThreatHuntingView(payload) {
    const safePayload = asObject(payload);
    initializeThreatHuntingWorkspace(safePayload);
    renderThreatHuntingTables(safePayload);
    renderThreatHuntingWorkspace(safePayload);
    updateThreatHuntingMetaIndicators(safePayload);
}

function renderThreatHuntingTables(payload) {
    const safePayload = asObject(payload);
    const hotBody = document.getElementById("hotSourcesRows");
    const findingsBody = document.getElementById("highConfidenceFindingsRows");
    const findingsSummary = document.getElementById("highConfidenceFindingsSummary");
    if (!hotBody) return;
    const searchTerm = getSearchTerm();
    const hotSources = filterBySearch(safePayload.hot_sources, searchTerm);
    const meta = asObject(safePayload.meta);
    const criteria = asObject(meta.high_confidence_criteria);
    const certaintyLevels = asArray(criteria.certainty_levels)
        .map((level) => normalizeCertaintyLevel(level))
        .filter((level, index, levels) => level && levels.indexOf(level) === index);
    const allFindings = (() => {
        const preferred = asArray(safePayload.high_confidence_findings);
        if (preferred.length) return preferred;
        const legacy = asArray(safePayload.high_confidence_incidents);
        if (legacy.length) return legacy;
        return asArray(safePayload.high_confidence_attack_incidents);
    })();
    const highConfidenceFindings = filterBySearch(allFindings, searchTerm);
    hotBody.innerHTML = hotSources.map((item) => {
        const typing = normalizeAttackSnapshot(item);
        return `<tr>
        <td class="mono">${escapeHtml(item.ip)}</td>
        <td>${escapeHtml(item.count)}</td>
        <td>${escapeHtml(typing.primaryClass)}</td>
        <td>${escapeHtml(fmtConfidence(typing.attackConfidence, 2))}</td>
        <td>${escapeHtml(certaintyLevelLabel(typing.certaintyLevel))}</td>
    </tr>`;
    }).join("") || `<tr><td colspan="5">${escapeHtml(buildEmptyStateMessage("No hot sources", searchTerm))}</td></tr>`;
    if (findingsSummary) {
        const thresholdLabel = fmtConfidence(criteria.attack_confidence_gte, 0);
        const certaintyLabel = certaintyLevels.length
            ? certaintyLevels.map((level) => certaintyLevelLabel(level)).join(", ")
            : "Probable, Certain";
        const totalMatched = Number.isFinite(Number(meta.high_confidence_total_candidates))
            ? toSafeCount(meta.high_confidence_total_candidates)
            : allFindings.length;
        findingsSummary.textContent = `${fmtNumber(highConfidenceFindings.length)} shown · ${fmtNumber(totalMatched)} matched criteria (confidence ≥ ${thresholdLabel}, certainty: ${certaintyLabel})`;
    }
    if (!findingsBody) return;
    findingsBody.innerHTML = highConfidenceFindings.map((item) => {
        const safeItem = asObject(item);
        const typing = resolveAttackTypingDisplay(safeItem);
        const incidentId = String(safeItem.id ?? "--");
        const timestamp = safeItem.timestamp ? String(safeItem.timestamp).slice(0, 19).replace("T", " ") : "--";
        const source = String(safeItem.attacker_ip ?? safeItem.source_ip ?? "--").trim() || "--";
        const targetIps = normalizeStringList(safeItem.target_ips);
        const targetIp = String(safeItem.target_ip ?? "").trim();
        if (targetIp && !targetIps.includes(targetIp)) targetIps.unshift(targetIp);
        const target = targetIps.length > 1 ? `${targetIps[0]} +${targetIps.length - 1}` : (targetIps[0] || "--");
        const severity = String(safeItem.severity || "LOW");
        return `<tr class="interactive high-confidence-finding-row" data-incident-id="${escapeHtml(incidentId)}">
        <td class="mono">${escapeHtml(incidentId)}</td>
        <td class="mono">${escapeHtml(timestamp)}</td>
        <td class="mono">${escapeHtml(source)}</td>
        <td class="mono">${escapeHtml(target)}</td>
        <td>
            <div class="cell-stack">
                <div>${escapeHtml(typing.primaryClass)}</div>
                <div class="cell-meta">${escapeHtml(shortText(typing.summary, 78))}</div>
            </div>
        </td>
        <td><span class="tag ${severityTagClass(severity)}">${escapeHtml(severity)}</span></td>
        <td>
            <div class="cell-stack">
                <div>${escapeHtml(fmtConfidence(typing.attackConfidence, 2))}</div>
                <div class="cell-meta">certainty: ${escapeHtml(certaintyLevelLabel(typing.certaintyLevel))}</div>
            </div>
        </td>
    </tr>`;
    }).join("") || `<tr><td colspan="7">${escapeHtml(buildEmptyStateMessage("No high-confidence findings", searchTerm))}</td></tr>`;
    findingsBody.querySelectorAll(".high-confidence-finding-row").forEach((row) => {
        row.addEventListener("click", () => {
            const incidentId = String(row.dataset.incidentId ?? "");
            const found = asArray(allFindings).find((incident) => String(asObject(incident).id ?? "") === incidentId)
                || state.incidents.find((incident) => String(asObject(incident).id ?? "") === incidentId);
            if (found) openIncidentModal(found);
        });
    });
}

function renderComplianceLog(payload) {
    const safePayload = asObject(payload);
    const searchTerm = getSearchTerm();
    const allLines = asArray(safePayload.lines).map((line) => String(line ?? ""));
    const lines = searchTerm
        ? allLines.filter((line) => line.toLowerCase().includes(searchTerm))
        : allLines;
    const body = document.getElementById("complianceLogBody");
    if (!body) return;
    body.textContent = lines.join("\n") || buildEmptyStateMessage("No logs available", searchTerm);
}

function renderSensorsTable(payload) {
    const safePayload = asObject(payload);
    const body = document.getElementById("sensorRows");
    if (!body) return;
    const searchTerm = getSearchTerm();
    const sensors = filterBySearch(safePayload.sensors, searchTerm);
    body.innerHTML = sensors.map((s) => `
        <tr>
            <td>${escapeHtml(s.id)}</td>
            <td class="mono">${escapeHtml(s.interface)}</td>
            <td>${escapeHtml(s.status)}</td>
            <td>${escapeHtml(fmtNumber(s.packets_processed))}</td>
        </tr>
    `).join("") || `<tr><td colspan="4">${escapeHtml(buildEmptyStateMessage("No sensors", searchTerm))}</td></tr>`;
}

function rerenderCurrentViewForSearch() {
    const view = state.currentView;
    if (!isViewSearchable(view)) return true;
    if (view === "command-center") {
        const hasData = !!asObject(state.viewLoadState[view]).hasData;
        if (!hasData && !state.incidents.length) return false;
        renderCommandCenterIncidentTable();
        return true;
    }
    if (view === "active-incidents") {
        const hasData = !!asObject(state.viewLoadState[view]).hasData;
        if (!hasData && !state.incidents.length) return false;
        renderActiveIncidentTable();
        return true;
    }
    if (view === "network-graph") {
        if (!state.cachedViewData.networkGraph) return false;
        renderNetworkGraphView(state.cachedViewData.networkGraph);
        return true;
    }
    if (view === "threat-map") {
        if (!state.cachedViewData.threatMap) return false;
        renderThreatMapTable(state.cachedViewData.threatMap);
        return true;
    }
    if (view === "threat-hunting") {
        if (!state.cachedViewData.hunting) return false;
        renderThreatHuntingView(state.cachedViewData.hunting);
        return true;
    }
    if (view === "compliance-logs") {
        if (!state.cachedViewData.compliance) return false;
        renderComplianceLog(state.cachedViewData.compliance);
        return true;
    }
    if (view === "sensor-nodes") {
        if (!state.cachedViewData.sensors) return false;
        renderSensorsTable(state.cachedViewData.sensors);
        return true;
    }
    return false;
}

function ensureChartDefaults() {
    Chart.defaults.color = "#888888";
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.borderColor = "#222222";
}

function setTrafficChart(chartData) {
    const ctx = document.getElementById("trafficChart");
    if (!ctx) return;
    const source = asObject(chartData);
    const data = {
        labels: asArray(source.labels),
        datasets: [
            {
                label: "Ingress Volume (MB/s)",
                data: asArray(source.ingress_volume_mb_s),
                borderColor: "#3b82f6",
                backgroundColor: "rgba(59,130,246,0.2)",
                fill: true,
                tension: 0.35,
            },
            {
                label: "Anomalous Packets",
                data: asArray(source.anomalous_packets),
                borderColor: "#ef4444",
                backgroundColor: "rgba(239,68,68,0.2)",
                fill: true,
                tension: 0.35,
            },
        ],
    };
    const signature = chartSignature(data);
    if (state.chartSignatures.traffic === signature) {
        return;
    }
    state.chartSignatures.traffic = signature;
    if (!trafficChart) {
        trafficChart = new Chart(ctx.getContext("2d"), {
            type: "line",
            data,
            options: { responsive: true, maintainAspectRatio: false, animation: false },
        });
        return;
    }
    trafficChart.data = data;
    trafficChart.update("none");
}

function setRadarChart(chartData) {
    const ctx = document.getElementById("radarChart");
    if (!ctx) return;
    const source = asObject(chartData);
    const data = {
        labels: asArray(source.labels),
        datasets: [
            {
                label: "Current Window",
                data: asArray(source.values),
                backgroundColor: "rgba(139,92,246,0.2)",
                borderColor: "#8b5cf6",
                pointBackgroundColor: "#8b5cf6",
                borderWidth: 2,
            },
        ],
    };
    const signature = chartSignature(data);
    if (state.chartSignatures.radar === signature) {
        return;
    }
    state.chartSignatures.radar = signature;
    if (!radarChart) {
        radarChart = new Chart(ctx.getContext("2d"), {
            type: "radar",
            data,
            options: { responsive: true, maintainAspectRatio: false, animation: false },
        });
        return;
    }
    radarChart.data = data;
    radarChart.update("none");
}

function setBarChart(chartData) {
    const ctx = document.getElementById("barChart");
    if (!ctx) return;
    const source = asObject(chartData);
    const data = {
        labels: asArray(source.labels),
        datasets: [
            {
                label: "Blocked Requests",
                data: asArray(source.values),
                backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6", "#10b981", "#8b5cf6", "#94a3b8", "#eab308", "#14b8a6"],
            },
        ],
    };
    const signature = chartSignature(data);
    if (state.chartSignatures.bar === signature) {
        return;
    }
    state.chartSignatures.bar = signature;
    if (!barChart) {
        barChart = new Chart(ctx.getContext("2d"), {
            type: "bar",
            data,
            options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } } },
        });
        return;
    }
    barChart.data = data;
    barChart.update("none");
}

async function loadCommandCenter() {
    const [summaryResp, chartsResp, incidentsResp, simulationResp] = await Promise.all([
        fetchJson("/api/overview/summary"),
        fetchJson("/api/overview/charts"),
        fetchJson("/api/incidents?limit=200"),
        fetchJson("/api/simulation/scenarios"),
    ]);
    const summary = asObject(summaryResp);
    const charts = asObject(chartsResp);
    const incidentsPayload = asObject(incidentsResp);
    const simulationPayload = asObject(simulationResp);
    state.incidents = asArray(incidentsPayload.items);
    state.simulation.scenarios = asArray(simulationPayload.items)
        .map((item) => normalizeSimulationScenario(item))
        .filter((item) => !!item);

    document.getElementById("kpi-events").textContent = fmtNumber(summary.events_processed);
    document.getElementById("kpi-threats").textContent = fmtNumber(summary.threats_blocked);
    document.getElementById("kpi-critical").textContent = fmtNumber(summary.active_critical_incidents);
    document.getElementById("kpi-confidence").textContent = fmtPct(summary.ai_confidence_score_pct);

    renderSimulationScenarioButtons();
    setTrafficChart(asObject(charts.traffic));
    setRadarChart(asObject(charts.threat_vectors));
    setBarChart(asObject(charts.top_endpoints));
    renderCommandCenterIncidentTable();
    renderAttackObservabilityWidget(incidentsPayload.meta);
    setViewMetaIndicators("command-center", [
        { label: "Summary", meta: summary.meta },
        { label: "Traffic", meta: asObject(charts.traffic).meta },
        { label: "Threat Vectors", meta: asObject(charts.threat_vectors).meta },
        { label: "Incidents", meta: incidentsPayload.meta },
        { label: "Simulations", meta: simulationPayload.meta },
    ]);
}

async function loadNetworkGraph() {
    if (shouldDeferNetworkGraphRefresh()) {
        return;
    }
    const payload = asObject(await fetchJson("/api/network/graph"));
    if (shouldDeferNetworkGraphRefresh()) {
        return;
    }
    state.cachedViewData.networkGraph = payload;
    renderNetworkGraphView(payload);
    setViewMetaIndicators("network-graph", [{ label: "Graph", meta: payload.meta }]);
}

async function loadThreatMap() {
    const payload = asObject(await fetchJson("/api/threat-intel?limit=400"));
    state.cachedViewData.threatMap = payload;
    renderThreatIntelView(payload);
    setViewMetaIndicators("threat-map", [{ label: "Threat Intel", meta: payload.meta }]);
}

async function loadActiveIncidents() {
    const payload = asObject(await fetchJson("/api/incidents?limit=500"));
    state.incidents = asArray(asObject(payload).items);
    renderActiveIncidentTable();
    setViewMetaIndicators("active-incidents", [{ label: "Incidents", meta: payload.meta }]);
}

async function loadThreatHunting() {
    const [huntingResponse, capabilitiesResponse] = await Promise.allSettled([
        fetchJson("/api/hunting"),
        fetchJson("/api/hunting/capabilities"),
    ]);
    if (huntingResponse.status !== "fulfilled") {
        throw huntingResponse.reason;
    }
    const payload = asObject(huntingResponse.value);
    state.cachedViewData.hunting = payload;
    if (capabilitiesResponse.status === "fulfilled") {
        state.hunting.capabilities = asObject(capabilitiesResponse.value);
    } else if (!state.hunting.capabilities) {
        setStatusMessage("huntingQueryStatus", "Hunting capabilities unavailable. Query workspace is running in fallback mode.", "pending");
    }
    renderThreatHuntingView(payload);
}

async function loadCompliance() {
    const payload = asObject(await fetchJson("/api/compliance/logs?tail=250"));
    state.cachedViewData.compliance = payload;
    renderComplianceLog(payload);
    setViewMetaIndicators("compliance-logs", [{ label: "Logs", meta: payload.meta }]);
}

async function loadRules() {
    const payload = asObject(await fetchJson("/api/config/rules"));
    const attackTyping = payload.attack_typing || {};
    document.getElementById("ruleThreshold").value = payload.alert_threshold;
    document.getElementById("ruleLoopWindow").value = payload.loopback_window_seconds;
    document.getElementById("ruleLoopPorts").value = payload.loopback_min_distinct_ports_for_scan;
    document.getElementById("ruleAttackMinScore").value = attackTyping.minimum_score ?? 0;
    document.getElementById("ruleAttackMinMargin").value = attackTyping.minimum_margin ?? 0;
    document.getElementById("ruleAttackFallbackClass").value = attackTyping.fallback_class_id ?? "unknown";
    document.getElementById("ruleAttackMaxAlternatives").value = attackTyping.max_alternatives ?? 3;
    setInputInvalidState(
        [
            "ruleThreshold",
            "ruleLoopWindow",
            "ruleLoopPorts",
            "ruleAttackMinScore",
            "ruleAttackMinMargin",
            "ruleAttackFallbackClass",
            "ruleAttackMaxAlternatives",
        ],
        new Set()
    );
    setStatusMessage("rulesStatus", "");
    setViewMetaIndicators("detection-rules", [{ label: "Rules", meta: payload.meta }]);
}

async function saveRules(body) {
    const payload = await fetchJson("/api/config/rules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    return asObject(payload);
}

async function loadSensors() {
    const payload = asObject(await fetchJson("/api/config/sensors"));
    state.cachedViewData.sensors = payload;
    renderSensorsTable(payload);
    setViewMetaIndicators("sensor-nodes", [{ label: "Sensors", meta: payload.meta }]);
}

async function loadSettings() {
    const payload = asObject(await fetchJson("/api/config/settings"));
    document.getElementById("settingHost").value = payload.host;
    document.getElementById("settingPort").value = payload.port;
    document.getElementById("settingRefresh").value = payload.refresh_interval_seconds;
    document.getElementById("settingStaged").checked = !!payload.enable_staged_data;
    state.refreshIntervalMs = Math.max(1000, Number(payload.refresh_interval_seconds) * 1000);
    setInputInvalidState(["settingRefresh"], new Set());
    setStatusMessage("settingsStatus", "");
    setViewMetaIndicators("settings", [{ label: "Settings", meta: payload.meta }]);
}

async function saveSettings(body) {
    const payload = await fetchJson("/api/config/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    state.refreshIntervalMs = Math.max(1000, Number(payload.refresh_interval_seconds) * 1000);
    restartPolling();
    return asObject(payload);
}

function openIncidentModal(incident) {
    const safeIncident = asObject(incident);
    const typing = resolveAttackTypingDisplay(safeIncident);
    const severity = safeIncident.severity || "N/A";
    const primaryConfidenceLabel = typing.primaryConfidence === null
        ? "Confidence unavailable (insufficient evidence)"
        : fmtConfidence(typing.primaryConfidence);
    const titleClass = typing.summary || typing.primaryClass || "Unknown / Needs More Data";
    document.getElementById("modTitle").textContent = `${safeIncident.id || "INC-UNKNOWN"} : ${titleClass}`;
    document.getElementById("modIp").textContent = safeIncident.attacker_ip || safeIncident.source_ip || "--";
    const targetIps = Array.from(new Set(
        asArray(safeIncident.target_ips)
            .map((value) => String(value ?? "").trim())
            .filter(Boolean)
    ));
    if (!targetIps.length) {
        const fallbackTarget = String(safeIncident.target_ip ?? "").trim();
        if (fallbackTarget) targetIps.push(fallbackTarget);
    }
    const targetPorts = asArray(safeIncident.target_ports)
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value > 0);
    let targetDisplay = targetIps.length ? targetIps.join(", ") : "--";
    if (targetPorts.length) {
        targetDisplay = `${targetDisplay} · ports: ${targetPorts.join(", ")}`;
    }
    document.getElementById("modTarget").textContent = targetDisplay;
    document.getElementById("modPrimaryClass").textContent = typing.primaryClass;
    document.getElementById("modPrimaryConfidence").textContent = primaryConfidenceLabel;
    state.modal.descriptionFullText = String(typing.description ?? "").trim() || "No description available";
    state.modal.descriptionBriefText = shortText(state.modal.descriptionFullText, 220);
    setModalDescriptionMode("brief");
    document.getElementById("modMethod").textContent = typing.method
        ? typing.method
        : "No detection method/source details available";
    document.getElementById("modUncertaintyNote").textContent = typing.uncertaintyNote;
    const alternativesEl = document.getElementById("modAlternatives");
    alternativesEl.innerHTML = typing.alternatives.length
        ? typing.alternatives
            .map((candidate) => `<li>${escapeHtml(formatAlternative(candidate))}</li>`)
            .join("")
        : "<li class=\"list-empty\">No alternatives reported</li>";
    document.getElementById("modEvidenceUsed").innerHTML = renderListItems(
        typing.evidenceUsed,
        "No supporting evidence reported"
    );
    document.getElementById("modEvidenceMissing").innerHTML = renderListItems(
        typing.evidenceMissing,
        "No missing evidence reported"
    );
    document.getElementById("modLimitations").innerHTML = renderListItems(
        typing.limitations,
        "No model limitations reported"
    );
    const rationaleEl = document.getElementById("modRationale");
    rationaleEl.innerHTML = renderListItems(typing.rationale, "No rationale available");
    document.getElementById("modCode").textContent = safeIncident.payload_preview || "No payload preview";
    const sev = document.getElementById("modSev");
    sev.textContent = severity;
    sev.className = `tag ${severityTagClass(severity)}`;
    document.getElementById("appModal").classList.add("active");
}

function closeIncidentModal() {
    document.getElementById("appModal").classList.remove("active");
}

function attachActions() {
    const exportIncidentsCsvBtn = document.getElementById("exportIncidentsCsv");
    if (exportIncidentsCsvBtn) {
        exportIncidentsCsvBtn.addEventListener("click", async () => {
            setStatusMessage("incidentExportStatus", "Preparing incident CSV export...", "pending");
            setButtonLoadingState("exportIncidentsCsv", true, "Exporting...");
            try {
                const filename = await exportIncidentsFile("csv", 1000);
                setStatusMessage("incidentExportStatus", `Downloaded ${filename}`, "success");
            } catch (error) {
                setStatusMessage(
                    "incidentExportStatus",
                    String(error?.message ?? "Failed to export incidents"),
                    "error"
                );
            } finally {
                setButtonLoadingState("exportIncidentsCsv", false);
            }
        });
    }
    document.getElementById("saveRules").addEventListener("click", async () => {
        const validation = validateRulesForm();
        if (!validation.ok) {
            setStatusMessage("rulesStatus", validation.message, "error");
            return;
        }
        setStatusMessage("rulesStatus", "Saving rules...", "pending");
        setButtonLoadingState("saveRules", true, "Saving...");
        try {
            const payload = await saveRules(validation.body);
            const attackTyping = asObject(payload.attack_typing);
            setStatusMessage(
                "rulesStatus",
                `Saved: threshold=${payload.alert_threshold}, min_score=${attackTyping.minimum_score}, min_margin=${attackTyping.minimum_margin}`,
                "success"
            );
            setViewMetaIndicators("detection-rules", [{ label: "Rules", meta: payload.meta }]);
        } catch (error) {
            setStatusMessage("rulesStatus", String(error?.message ?? "Failed to save rules"), "error");
        } finally {
            setButtonLoadingState("saveRules", false);
        }
    });
    document.getElementById("saveSettings").addEventListener("click", async () => {
        const validation = validateSettingsForm();
        if (!validation.ok) {
            setStatusMessage("settingsStatus", validation.message, "error");
            return;
        }
        setStatusMessage("settingsStatus", "Saving settings...", "pending");
        setButtonLoadingState("saveSettings", true, "Saving...");
        try {
            const payload = await saveSettings(validation.body);
            setStatusMessage("settingsStatus", "Settings saved", "success");
            setViewMetaIndicators("settings", [{ label: "Settings", meta: payload.meta }]);
        } catch (error) {
            setStatusMessage("settingsStatus", String(error?.message ?? "Failed to save settings"), "error");
        } finally {
            setButtonLoadingState("saveSettings", false);
        }
    });
    document.getElementById("refreshNow").addEventListener("click", () => loadCurrentView());
    const graphFitBtn = document.getElementById("networkGraphFit");
    if (graphFitBtn) {
        graphFitBtn.addEventListener("click", () => fitNetworkGraph());
    }
    const graphPhysicsBtn = document.getElementById("networkGraphPhysicsToggle");
    if (graphPhysicsBtn) {
        graphPhysicsBtn.addEventListener("click", () => {
            setNetworkGraphPhysicsEnabled(!state.networkGraph.physicsEnabled);
        });
    }
    const threatMapFitBtn = document.getElementById("threatIntelMapFit");
    if (threatMapFitBtn) {
        threatMapFitBtn.addEventListener("click", () => {
            ensureThreatIntelMap();
            fitThreatIntelMapToMarkers({ announce: true });
        });
    }
    const threatMapResetBtn = document.getElementById("threatIntelMapReset");
    if (threatMapResetBtn) {
        threatMapResetBtn.addEventListener("click", () => {
            resetThreatIntelMapView();
        });
    }
    const threatMapFocusBtn = document.getElementById("threatIntelMapFocusSelected");
    if (threatMapFocusBtn) {
        threatMapFocusBtn.addEventListener("click", () => {
            focusThreatIntelSelectedRow({ openView: false });
        });
    }
    const simulationButtons = document.getElementById("simulationScenarioButtons");
    if (simulationButtons) {
        simulationButtons.addEventListener("click", async (event) => {
            const targetButton = event.target.closest(".simulation-trigger-btn");
            if (!targetButton || targetButton.disabled) return;
            const scenarioId = String(targetButton.dataset.scenarioId ?? "").trim();
            if (!scenarioId) return;
            const scenario = state.simulation.scenarios.find((item) => item.id === scenarioId);
            const scenarioName = scenario?.name || scenarioId;
            const triggerCount = Math.max(1, Number(scenario?.triggerCount) || 1);
            setStatusMessage("simulationStatus", `Triggering ${scenarioName}...`, "pending");
            setSimulationTriggerLoading(true, scenarioId);
            try {
                const payload = await triggerSimulationScenario(scenarioId, triggerCount);
                const triggeredCount = Math.max(0, Number(payload.count) || 0);
                const triggeredScenario = asObject(payload.scenario);
                const triggeredName = String(triggeredScenario.name ?? scenarioName).trim() || scenarioName;
                clearViewFeedback("command-center");
                try {
                    await loadCommandCenter();
                    markViewLoaded("command-center");
                    setStatusMessage(
                        "simulationStatus",
                        `Triggered ${triggeredName} (${triggeredCount} incident${triggeredCount === 1 ? "" : "s"}). Dashboard refreshed.`,
                        "success"
                    );
                } catch (refreshError) {
                    const hasStaleData = !!asObject(state.viewLoadState["command-center"]).hasData;
                    showViewError("command-center", refreshError, hasStaleData);
                    setStatusMessage(
                        "simulationStatus",
                        `Triggered ${triggeredName} (${triggeredCount} incident${triggeredCount === 1 ? "" : "s"}), but dashboard refresh failed.`,
                        "error"
                    );
                }
            } catch (error) {
                setStatusMessage("simulationStatus", String(error?.message ?? "Failed to trigger simulation"), "error");
            } finally {
                setSimulationTriggerLoading(false);
            }
        });
    }
    const huntingRunBtn = document.getElementById("huntingRunQuery");
    if (huntingRunBtn) {
        huntingRunBtn.addEventListener("click", () => {
            executeThreatHuntingQuery();
        });
    }
    const huntingResetBtn = document.getElementById("huntingResetQuery");
    if (huntingResetBtn) {
        huntingResetBtn.addEventListener("click", () => {
            resetThreatHuntingQueryWorkspace();
        });
    }
    const huntingMethodContainer = document.getElementById("huntingScientificMethods");
    if (huntingMethodContainer) {
        huntingMethodContainer.addEventListener("change", () => {
            state.hunting.selectedScientificMethods = getSelectedScientificMethods();
        });
    }
    const huntingDslInput = document.getElementById("huntingDslInput");
    if (huntingDslInput) {
        huntingDslInput.addEventListener("keydown", (event) => {
            if (!(event.ctrlKey || event.metaKey) || event.key !== "Enter") return;
            event.preventDefault();
            executeThreatHuntingQuery();
        });
    }
    const searchInput = document.getElementById("globalSearch");
    if (searchInput) {
        state.searchTerm = searchInput.value || "";
        searchInput.addEventListener("input", () => {
            state.searchTerm = searchInput.value || "";
            debounceViewReload();
        });
    }
    document.getElementById("modalClose").addEventListener("click", closeIncidentModal);
    const descriptionToggle = document.getElementById("modDescriptionToggle");
    if (descriptionToggle) {
        descriptionToggle.addEventListener("click", (event) => {
            const targetButton = event.target.closest(".description-toggle-btn");
            if (!targetButton) return;
            setModalDescriptionMode(targetButton.dataset.descriptionMode);
        });
    }
    document.getElementById("appModal").addEventListener("click", (event) => {
        if (event.target.id === "appModal") closeIncidentModal();
    });
    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        const modal = document.getElementById("appModal");
        if (modal && modal.classList.contains("active")) {
            closeIncidentModal();
        }
    });
}

async function loadCurrentView() {
    const requestedView = state.currentView;
    const currentLoadState = asObject(state.viewLoadState[requestedView]);
    if (currentLoadState.isLoading) {
        return;
    }
    state.viewLoadState[requestedView] = {
        ...currentLoadState,
        isLoading: true,
    };
    clearViewFeedback(requestedView);
    try {
        if (requestedView === "command-center") await loadCommandCenter();
        else if (requestedView === "network-graph") await loadNetworkGraph();
        else if (requestedView === "threat-map") await loadThreatMap();
        else if (requestedView === "active-incidents") await loadActiveIncidents();
        else if (requestedView === "threat-hunting") await loadThreatHunting();
        else if (requestedView === "compliance-logs") await loadCompliance();
        else if (requestedView === "detection-rules") await loadRules();
        else if (requestedView === "sensor-nodes") await loadSensors();
        else if (requestedView === "settings") await loadSettings();
        else {
            setView("command-center");
            return;
        }
        markViewLoaded(requestedView);
    } catch (error) {
        const hasStaleData = !!asObject(state.viewLoadState[requestedView]).hasData;
        showViewError(requestedView, error, hasStaleData);
        console.error(error);
    } finally {
        state.viewLoadState[requestedView] = {
            ...asObject(state.viewLoadState[requestedView]),
            isLoading: false,
        };
    }
}

function restartPolling() {
    if (state.pollTimer) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
    }
    state.pollTimer = setInterval(() => {
        if (isViewAutoRefreshEnabled(state.currentView)) {
            if (shouldDeferNetworkGraphRefresh()) {
                return;
            }
            loadCurrentView();
        }
    }, state.refreshIntervalMs);
}

function bootstrapRoute() {
    const hash = window.location.hash.replace("#", "").trim();
    const available = new Set(Array.from(document.querySelectorAll(".view")).map((v) => v.dataset.view));
    if (hash && available.has(hash)) {
        state.currentView = hash;
        setView(hash);
    } else {
        setView("command-center");
    }
    window.addEventListener("hashchange", () => {
        const next = window.location.hash.replace("#", "").trim();
        if (next && available.has(next) && next !== state.currentView) {
            setView(next);
        }
    });
}

async function main() {
    ensureChartDefaults();
    attachNavigation();
    attachActions();
    updateClock();
    setInterval(updateClock, 1000);

    await loadSettings().catch(() => {});
    bootstrapRoute();
    restartPolling();
}

main().catch((error) => console.error(error));
