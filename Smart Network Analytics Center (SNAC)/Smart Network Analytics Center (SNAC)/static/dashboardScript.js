let allDevices = [];
let deviceStatusChart;
let latencyTrendChart;
let trafficUsageChart;
let refreshTimer;
let scanTimer;
let scanInProgress = false;
const refreshIntervals = new Set(["10000", "30000", "60000", "300000"]);
const defaultSettings = {
    scanInterval: "10000",
    pingTimeout: "1000",
    autoRefresh: true,
    latencyThreshold: "50",
    offlineAlerts: true,
    emailNotifications: false,
    theme: "cyber",
    lastScanTime: "Not Available"
};

function updateClock() {
    const now = new Date();
    document.getElementById("clock").innerText = now.toLocaleTimeString();
    document.getElementById("settingsCurrentTime").innerText = now.toLocaleTimeString();
}

async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (response.status === 401) {
        window.location.href = "/";
        return null;
    }
    return response.json();
}

async function loadSummary() {
    const data = await fetchJson("/api/summary");
    if (!data) {
        return;
    }

    document.getElementById("totalDevices").innerText = data.totalDevices;
    document.getElementById("activeDevices").innerText = data.activeDevices;
    document.getElementById("offlineDevices").innerText = data.offlineDevices;
    document.getElementById("networkHealth").innerText = data.networkHealth;
    document.getElementById("latency").innerText = data.latency;
    document.getElementById("traffic").innerText = data.traffic;

    updateAlert(data.alert);
    updateDeviceStatusChart(data.activeDevices, data.offlineDevices);
}

async function loadDevices() {
    const data = await fetchJson("/api/devices");
    if (!data) {
        return;
    }

    allDevices = data.devices;
    renderDevices();
    renderNetworkMap();
    // Update traffic chart now that devices are loaded
    updateTrafficChart();
}

function renderDevices() {
    const deviceBody = document.getElementById("deviceBody");
    const searchInput = document.getElementById("deviceSearch");
    const searchTerm = (searchInput?.value || "").trim().toLowerCase();
    deviceBody.innerHTML = "";

    const filteredDevices = allDevices.filter((device) => {
        const searchableText = [
            device.name,
            device.ip_address,
            device.mac_address || "Unknown",
            device.device_type
        ].join(" ").toLowerCase();

        return searchableText.includes(searchTerm);
    });

    filteredDevices.forEach((device) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${device.name}</td>
            <td class="${device.status === "Online" ? "online" : "offline"}">${device.status}</td>
            <td>${device.ip_address}</td>
            <td>${device.mac_address || "Unknown"}</td>
            <td>${device.device_type || "Unknown"}</td>
        `;
        deviceBody.appendChild(row);
    });
}

function updateAlert(alert) {
    const alertBox = document.getElementById("alertBox");
    alertBox.innerText = alert.message;
    const colors = getThemeColors();

    if (alert.level === "critical") {
        alertBox.style.borderLeft = `5px solid ${colors.danger}`;
        alertBox.style.boxShadow = `0 12px 28px ${colors.dangerGlow}`;
        return;
    }

    if (alert.level === "warning") {
        alertBox.style.borderLeft = `5px solid ${colors.warning}`;
        alertBox.style.boxShadow = `0 12px 28px ${colors.warningGlow}`;
        return;
    }

    alertBox.style.borderLeft = `5px solid ${colors.success}`;
    alertBox.style.boxShadow = `0 12px 28px ${colors.successGlow}`;
}

function getThemeColors() {
    const styles = getComputedStyle(document.body);
    return {
        danger: styles.getPropertyValue("--app-danger").trim() || "#fb7185",
        warning: styles.getPropertyValue("--app-warning").trim() || "#fbbf24",
        success: styles.getPropertyValue("--app-success").trim() || "#34d399",
        dangerGlow: "rgba(251, 113, 133, 0.24)",
        warningGlow: "rgba(251, 191, 36, 0.22)",
        successGlow: "rgba(52, 211, 153, 0.22)"
    };
}

async function refreshDashboard() {
    await loadSummary();
    await loadDevices();
}

async function scanNetwork() {
    if (scanInProgress) {
        return;
    }

    scanInProgress = true;
    try {
        const data = await fetchJson("/api/scan", { method: "POST" });
        if (data?.scannedAt) {
            saveSetting("lastScanTime", new Date(data.scannedAt).toLocaleString());
            updateLastScanDisplay();
        }
        await refreshDashboard();
    } finally {
        scanInProgress = false;
    }
}

function showDashboardView() {
    document.getElementById("dashboardOverview").style.display = "block";
    document.getElementById("deviceSection").style.display = "none";
    document.getElementById("analyticsSection").style.display = "none";
    document.getElementById("networkMapSection").style.display = "none";
    document.getElementById("settingsSection").style.display = "none";
}

function showDevicesView() {
    document.getElementById("dashboardOverview").style.display = "block";
    document.getElementById("deviceSection").style.display = "block";
    document.getElementById("analyticsSection").style.display = "none";
    document.getElementById("networkMapSection").style.display = "none";
    document.getElementById("settingsSection").style.display = "none";
}

function showAnalyticsView() {
    document.getElementById("dashboardOverview").style.display = "none";
    document.getElementById("deviceSection").style.display = "none";
    document.getElementById("analyticsSection").style.display = "block";
    document.getElementById("networkMapSection").style.display = "none";
    document.getElementById("settingsSection").style.display = "none";
    initializeCharts();
}

function showNetworkMapView() {
    document.getElementById("dashboardOverview").style.display = "none";
    document.getElementById("deviceSection").style.display = "none";
    document.getElementById("analyticsSection").style.display = "none";
    document.getElementById("networkMapSection").style.display = "block";
    document.getElementById("settingsSection").style.display = "none";
    renderNetworkMap();
}

function showSettingsView() {
    document.getElementById("dashboardOverview").style.display = "none";
    document.getElementById("deviceSection").style.display = "none";
    document.getElementById("analyticsSection").style.display = "none";
    document.getElementById("networkMapSection").style.display = "none";
    document.getElementById("settingsSection").style.display = "block";
    updateLastScanDisplay();
}

function renderNetworkMap() {
    const canvas = document.getElementById("topologyCanvas");
    canvas.innerHTML = "";

    const devices = [...allDevices].sort(compareDevicesByIp);
    if (devices.length === 0) {
        const emptyState = document.createElement("div");
        emptyState.className = "topologyEmptyState";
        emptyState.innerText = "No devices detected";
        canvas.appendChild(emptyState);
        return;
    }

    const onlineCount = devices.filter((device) => device.status === "Online").length;
    const hub = createTopologyNode({
        name: "Detected Network",
        ip_address: summarizeNetworkRange(devices),
        status: onlineCount > 0 ? "Online" : "Offline",
        device_type: `${devices.length} devices`,
        mac_address: "Not applicable",
        latency_ms: 0,
        last_seen: mostRecentLastSeen(devices)
    }, true);

    const hubRow = document.createElement("div");
    hubRow.className = "topologyRow topologyRowSingle";
    hubRow.appendChild(hub);

    const connector = document.createElement("div");
    connector.className = "topologyConnector";

    const branch = document.createElement("div");
    branch.className = "topologyBranch topologyBranchDynamic";

    const deviceGrid = document.createElement("div");
    deviceGrid.className = "topologyDeviceGrid";
    devices.forEach((device) => {
        deviceGrid.appendChild(createTopologyNode(device, false));
    });

    canvas.appendChild(hubRow);
    canvas.appendChild(connector);
    canvas.appendChild(branch);
    canvas.appendChild(deviceGrid);
}

function createTopologyNode(device, isHub) {
    const status = device.status || "Offline";
    const node = document.createElement("button");
    node.className = `topologyNode ${status === "Online" ? "onlineNode" : "offlineNode"}`;
    if (isHub) {
        node.classList.add("topologyHubNode");
    }

    node.type = "button";
    node.dataset.deviceName = device.name || "Unknown";
    node.dataset.ipAddress = device.ip_address || "Unknown";
    node.dataset.macAddress = device.mac_address || "Unknown";
    node.dataset.status = status;
    node.dataset.deviceType = device.device_type || "Unknown";
    node.dataset.latency = Number.isFinite(Number(device.latency_ms)) ? `${device.latency_ms}ms` : "Unknown";
    node.dataset.lastSeen = formatLastSeen(device.last_seen);

    const statusDot = document.createElement("span");
    statusDot.className = "nodeStatusDot";

    const name = document.createElement("strong");
    name.className = "nodeName";
    name.innerText = node.dataset.deviceName;

    const ip = document.createElement("span");
    ip.className = "nodeIp";
    ip.innerText = node.dataset.ipAddress;

    const meta = document.createElement("span");
    meta.className = "nodeStatusText";
    meta.innerText = `${node.dataset.deviceType} - ${status}`;

    node.appendChild(statusDot);
    node.appendChild(name);
    node.appendChild(ip);
    node.appendChild(meta);
    return node;
}

function compareDevicesByIp(firstDevice, secondDevice) {
    return ipToNumber(firstDevice.ip_address) - ipToNumber(secondDevice.ip_address);
}

function ipToNumber(ipAddress = "") {
    const parts = ipAddress.split(".").map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
        return Number.MAX_SAFE_INTEGER;
    }
    return parts.reduce((total, part) => (total * 256) + part, 0);
}

function summarizeNetworkRange(devices) {
    const addresses = devices.map((device) => device.ip_address).filter(Boolean);
    if (addresses.length === 1) {
        return addresses[0];
    }

    return `${addresses[0]} - ${addresses[addresses.length - 1]}`;
}

function mostRecentLastSeen(devices) {
    const timestamps = devices
        .map((device) => Date.parse(device.last_seen))
        .filter((timestamp) => !Number.isNaN(timestamp));

    if (timestamps.length === 0) {
        return "Not available";
    }

    return new Date(Math.max(...timestamps)).toISOString();
}

function formatLastSeen(value) {
    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) {
        return value || "Not available";
    }
    return new Date(timestamp).toLocaleString();
}

function showNodeDetails(node) {
    document.getElementById("detailDeviceName").innerText = node.dataset.deviceName || "Unknown";
    document.getElementById("detailIpAddress").innerText = node.dataset.ipAddress || "Unknown";
    document.getElementById("detailMacAddress").innerText = node.dataset.macAddress || "Unknown";
    document.getElementById("detailStatus").innerText = node.dataset.status || "Unknown";
    document.getElementById("detailDeviceType").innerText = node.dataset.deviceType || "Unknown";
    document.getElementById("detailLatency").innerText = node.dataset.latency || "Unknown";
    document.getElementById("detailLastSeen").innerText = node.dataset.lastSeen || "Not available";
    document.getElementById("nodeDetailsPanel").classList.add("open");
}

function hideNodeDetails() {
    document.getElementById("nodeDetailsPanel").classList.remove("open");
}

function loadSettings() {
    const settings = getSettings();

    document.getElementById("scanInterval").value = settings.scanInterval;
    document.getElementById("pingTimeout").value = settings.pingTimeout;
    document.getElementById("autoRefresh").checked = settings.autoRefresh;
    document.getElementById("latencyThreshold").value = settings.latencyThreshold;
    document.getElementById("offlineAlerts").checked = settings.offlineAlerts;
    document.getElementById("emailNotifications").checked = settings.emailNotifications;
    const selectedTheme = document.querySelector(`input[name="themeSelector"][value="${settings.theme}"]`)
        || document.getElementById("themeCyber");
    selectedTheme.checked = true;

    applyTheme(settings.theme);
    updateLastScanDisplay();
    configureMonitoringTimers();
}

function getSettings() {
    return {
        scanInterval: getRefreshIntervalSetting(),
        pingTimeout: localStorage.getItem("netpulse.pingTimeout") || defaultSettings.pingTimeout,
        autoRefresh: readBooleanSetting("netpulse.autoRefresh", defaultSettings.autoRefresh),
        latencyThreshold: localStorage.getItem("netpulse.latencyThreshold") || defaultSettings.latencyThreshold,
        offlineAlerts: readBooleanSetting("netpulse.offlineAlerts", defaultSettings.offlineAlerts),
        emailNotifications: readBooleanSetting("netpulse.emailNotifications", defaultSettings.emailNotifications),
        theme: localStorage.getItem("netpulse.theme") || defaultSettings.theme,
        lastScanTime: localStorage.getItem("netpulse.lastScanTime") || defaultSettings.lastScanTime
    };
}

function getRefreshIntervalSetting() {
    const interval = localStorage.getItem("netpulse.scanInterval") || defaultSettings.scanInterval;
    if (refreshIntervals.has(interval)) {
        return interval;
    }
    return defaultSettings.scanInterval;
}

function readBooleanSetting(key, fallback) {
    const value = localStorage.getItem(key);
    if (value === null) {
        return fallback;
    }
    return value === "true";
}

function saveSetting(name, value) {
    localStorage.setItem(`netpulse.${name}`, value);
}

function bindSettingsControls() {
    document.getElementById("scanInterval").addEventListener("change", (event) => {
        const interval = refreshIntervals.has(event.target.value) ? event.target.value : defaultSettings.scanInterval;
        event.target.value = interval;
        saveSetting("scanInterval", interval);
        configureMonitoringTimers();
    });

    document.getElementById("pingTimeout").addEventListener("change", (event) => {
        saveSetting("pingTimeout", event.target.value);
    });

    document.getElementById("autoRefresh").addEventListener("change", (event) => {
        saveSetting("autoRefresh", event.target.checked);
        configureMonitoringTimers();
    });

    document.getElementById("latencyThreshold").addEventListener("input", (event) => {
        saveSetting("latencyThreshold", event.target.value || defaultSettings.latencyThreshold);
    });

    document.getElementById("offlineAlerts").addEventListener("change", (event) => {
        saveSetting("offlineAlerts", event.target.checked);
    });

    document.getElementById("emailNotifications").addEventListener("change", (event) => {
        saveSetting("emailNotifications", event.target.checked);
    });

    document.querySelectorAll('input[name="themeSelector"]').forEach((themeInput) => {
        themeInput.addEventListener("change", (event) => {
            saveSetting("theme", event.target.value);
            applyTheme(event.target.value);
        });
    });
}

function applyTheme(theme) {
    document.body.classList.remove("theme-dark", "theme-light");
    if (theme === "dark") {
        document.body.classList.add("theme-dark");
    }
    if (theme === "light") {
        document.body.classList.add("theme-light");
    }
    refreshChartThemes();
}

function configureMonitoringTimers() {
    const settings = getSettings();
    const interval = Number(settings.scanInterval);

    clearInterval(refreshTimer);
    clearInterval(scanTimer);

    if (!settings.autoRefresh) {
        return;
    }

    refreshTimer = setInterval(refreshDashboard, interval);
    scanTimer = setInterval(scanNetwork, interval);
}

function updateLastScanDisplay() {
    document.getElementById("lastScanTime").innerText = getSettings().lastScanTime;
}

function initializeCharts() {
    if (typeof Chart === "undefined") {
        return;
    }

    initializeDeviceStatusChart();
    initializeLatencyTrendChart();
    initializeTrafficUsageChart();
}

function initializeDeviceStatusChart() {
    if (deviceStatusChart) {
        return;
    }

    const palette = getChartPalette();
    const context = document.getElementById("deviceStatusChart");
    deviceStatusChart = new Chart(context, {
        type: "doughnut",
        data: {
            labels: ["Online", "Offline"],
            datasets: [{
                data: [
                    Number(document.getElementById("activeDevices").innerText) || 0,
                    Number(document.getElementById("offlineDevices").innerText) || 0
                ],
                backgroundColor: [palette.successFill, palette.dangerFill],
                borderColor: [palette.success, palette.danger],
                borderWidth: 1
            }]
        },
        options: buildChartOptions()
    });
}

function initializeLatencyTrendChart() {
    if (latencyTrendChart) {
        return;
    }

    const palette = getChartPalette();
    const context = document.getElementById("latencyTrendChart");
    latencyTrendChart = new Chart(context, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Latency (ms)",
                data: [],
                borderColor: palette.accent,
                backgroundColor: palette.accentFill,
                tension: 0.35,
                fill: true,
                pointBackgroundColor: palette.accent
            }]
        },
        options: buildChartOptions()
    });
}

function initializeTrafficUsageChart() {
    if (trafficUsageChart) {
        return;
    }

    const palette = getChartPalette();
    const context = document.getElementById("trafficUsageChart");
    trafficUsageChart = new Chart(context, {
        type: "bar",
        data: {
            labels: [],
            datasets: [{
                label: "Traffic Usage (GB)",
                data: [],
                backgroundColor: [],
                borderColor: palette.accent,
                borderWidth: 1
            }]
        },
        options: buildChartOptions()
    });
}

function updateTrafficChart() {
    if (!trafficUsageChart) return;

    // Use top 6 devices by traffic_gb for the chart
    const devices = [...allDevices].filter(d => Number(d.traffic_gb) > 0);
    devices.sort((a,b) => Number(b.traffic_gb) - Number(a.traffic_gb));
    const top = devices.slice(0, 6);

    const labels = top.map(d => d.name || d.ip_address || d.mac_address || "Unknown");
    const data = top.map(d => Math.round((Number(d.traffic_gb) || 0) * 100) / 100);

    const palette = getChartPalette();
    const bgColors = top.map((_, i) => i === 0 ? palette.accentFillStrong : palette.successFill);

    trafficUsageChart.data.labels = labels;
    trafficUsageChart.data.datasets[0].data = data;
    trafficUsageChart.data.datasets[0].backgroundColor = bgColors;
    trafficUsageChart.update();
}

function updateDeviceStatusChart(activeDevices, offlineDevices) {
    if (!deviceStatusChart) {
        return;
    }

    deviceStatusChart.data.datasets[0].data = [activeDevices, offlineDevices];
    deviceStatusChart.update();
}

function refreshChartThemes() {
    if (typeof Chart === "undefined") {
        return;
    }

    const palette = getChartPalette();

    if (deviceStatusChart) {
        deviceStatusChart.data.datasets[0].backgroundColor = [palette.successFill, palette.dangerFill];
        deviceStatusChart.data.datasets[0].borderColor = [palette.success, palette.danger];
        deviceStatusChart.options = buildChartOptions();
        deviceStatusChart.update();
    }

    if (latencyTrendChart) {
        latencyTrendChart.data.datasets[0].borderColor = palette.accent;
        latencyTrendChart.data.datasets[0].backgroundColor = palette.accentFill;
        latencyTrendChart.data.datasets[0].pointBackgroundColor = palette.accent;
        latencyTrendChart.options = buildChartOptions();
        latencyTrendChart.update();
    }

    if (trafficUsageChart) {
        trafficUsageChart.data.datasets[0].backgroundColor = [
            palette.accentFillStrong,
            palette.successFill
        ];
        trafficUsageChart.data.datasets[0].borderColor = palette.accent;
        trafficUsageChart.options = buildChartOptions();
        trafficUsageChart.update();
    }
}

function updateLatencyTrendChart() {
    if (!latencyTrendChart) {
        return;
    }

    const currentLatency = Number(document.getElementById("latency").innerText.replace("ms", "")) || 0;
    const simulatedLatency = Math.max(1, currentLatency + Math.floor(Math.random() * 11) - 5);
    const timeLabel = new Date().toLocaleTimeString();

    latencyTrendChart.data.labels.push(timeLabel);
    latencyTrendChart.data.datasets[0].data.push(simulatedLatency);

    if (latencyTrendChart.data.labels.length > 10) {
        latencyTrendChart.data.labels.shift();
        latencyTrendChart.data.datasets[0].data.shift();
    }

    latencyTrendChart.update();
}

function buildChartOptions() {
    const palette = getChartPalette();
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: palette.text
                }
            }
        },
        scales: {
            x: {
                ticks: {
                    color: palette.muted
                },
                grid: {
                    color: palette.grid
                }
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: palette.muted
                },
                grid: {
                    color: palette.grid
                }
            }
        }
    };
}

function getChartPalette() {
    const styles = getComputedStyle(document.body);
    const accent = styles.getPropertyValue("--app-accent").trim() || "#38bdf8";
    const success = styles.getPropertyValue("--app-success").trim() || "#34d399";
    const danger = styles.getPropertyValue("--app-danger").trim() || "#fb7185";
    const warning = styles.getPropertyValue("--app-warning").trim() || "#fbbf24";
    return {
        accent,
        success,
        danger,
        warning,
        text: styles.getPropertyValue("--app-text").trim() || "#e5edf6",
        muted: styles.getPropertyValue("--app-text-muted").trim() || "#9fb0c4",
        grid: styles.getPropertyValue("--app-border").trim() || "#3b4b64",
        accentFill: colorWithAlpha(accent, 0.16),
        accentFillStrong: colorWithAlpha(accent, 0.72),
        successFill: colorWithAlpha(success, 0.72),
        dangerFill: colorWithAlpha(danger, 0.72),
        warningFill: colorWithAlpha(warning, 0.72)
    };
}

function colorWithAlpha(color, alpha) {
    if (color.startsWith("#") && color.length === 7) {
        const red = parseInt(color.slice(1, 3), 16);
        const green = parseInt(color.slice(3, 5), 16);
        const blue = parseInt(color.slice(5, 7), 16);
        return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
    }
    return color;
}

document.getElementById("dashboardBtn").addEventListener("click", showDashboardView);
document.getElementById("devicesBtn").addEventListener("click", showDevicesView);
document.getElementById("networkMapBtn").addEventListener("click", showNetworkMapView);
document.getElementById("analyticsBtn").addEventListener("click", showAnalyticsView);
document.getElementById("settingsBtn").addEventListener("click", showSettingsView);
document.getElementById("deviceSearch").addEventListener("input", renderDevices);
document.getElementById("topologyCanvas").addEventListener("click", (event) => {
    const node = event.target.closest(".topologyNode");
    if (node) {
        showNodeDetails(node);
    }
});
document.getElementById("nodeDetailsClose").addEventListener("click", hideNodeDetails);

document.getElementById("logoutBtn").addEventListener("click", async () => {
    const data = await fetchJson("/api/logout", { method: "POST" });
    window.location.href = data?.redirect || "/";
});

updateClock();
setInterval(updateClock, 1000);

bindSettingsControls();
loadSettings();
initializeCharts();
scanNetwork();
setInterval(updateLatencyTrendChart, 5000);
