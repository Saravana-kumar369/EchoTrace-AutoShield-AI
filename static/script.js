const threatCtx = document.getElementById('threatChart').getContext('2d');

let threatData = {
    labels: ['DoS', 'Probe', 'R2L', 'U2R'],
    datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [
            'rgba(239, 68, 68, 0.8)',
            'rgba(245, 158, 11, 0.8)',
            'rgba(139, 92, 246, 0.8)',
            'rgba(236, 72, 153, 0.8)'
        ],
        borderWidth: 0,
        hoverOffset: 4
    }]
};

const threatChart = new Chart(threatCtx, {
    type: 'doughnut',
    data: threatData,
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } }
        },
        cutout: '70%'
    }
});

let lastAlertCount = 0;
let totalAnalyzed = 0;

function formatTime(timestamp) {
    const d = new Date(timestamp * 1000);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

async function fetchAlerts() {
    try {
        const res = await fetch('/alerts');
        const data = await res.json();
        updateDashboard(data.alerts, data.blocked_sessions);
    } catch (e) {
        console.error("Failed to fetch alerts", e);
    }
}

async function fetchBlocked() {
    try {
        const res = await fetch('/blocked_list');
        const data = await res.json();
        updateBlockedPanel(data.blocked);
    } catch (e) {}
}

function updateBlockedPanel(blocked) {
    const list = document.getElementById('blockedList');
    const entries = Object.entries(blocked);

    if (entries.length === 0) {
        list.innerHTML = '<div class="empty-state">No blocked sessions yet. Monitoring...</div>';
        return;
    }

    list.innerHTML = '';
    entries.forEach(([token, info]) => {
        const item = document.createElement('div');
        item.className = 'blocked-item';
        const blockedTime = new Date(info.blocked_at * 1000).toLocaleTimeString('en-US', { hour12: false });
        item.innerHTML = `
            <div class="bi-user">🚫 ${info.username}</div>
            <div class="bi-detail">
                <strong>IP:</strong> ${info.ip_address}<br>
                <strong>Attack:</strong> ${info.reason}<br>
                <strong>Session:</strong> ${token.substring(0, 12)}...<br>
                <strong>Blocked:</strong> ${blockedTime}
            </div>
        `;
        list.appendChild(item);
    });
}

function updateDashboard(alerts, blockedCount) {
    document.getElementById('blockedSessions').textContent = blockedCount || 0;

    const tbody = document.getElementById('alertBody');

    if (alerts.length !== lastAlertCount) {
        tbody.innerHTML = '';

        let localCount = { 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0 };
        let localBlocked = 0;

        alerts.forEach((alert, index) => {
            if (localCount[alert.label] !== undefined) localCount[alert.label]++;
            if (alert.action === 'BLOCK') localBlocked++;

            const tr = document.createElement('tr');
            if (index < 5) tr.classList.add('row-in');

            const badgeClass = alert.action === 'BLOCK' ? 'badge-block' : 'badge-alert';
            const ipColor = alert.action === 'BLOCK' ? '#ef4444' : '#f59e0b';

            tr.innerHTML = `
                <td>${formatTime(alert.timestamp)}</td>
                <td style="color: var(--accent-glow); font-weight: 600;">${alert.username || 'N/A'}</td>
                <td style="color: ${ipColor};">${alert.ip_address || 'unknown'}</td>
                <td style="font-weight: 700;">${alert.label} ${alert.ai_driven ? '<span style="background:rgba(56,189,248,0.2);color:#38bdf8;padding:1px 5px;border-radius:3px;font-size:0.65rem;margin-left:4px;">AI</span>' : ''}</td>
                <td>${(alert.confidence * 100).toFixed(1)}%</td>
                <td><span class="${badgeClass}">${alert.action}</span></td>
            `;
            tbody.appendChild(tr);
        });

        // Update chart
        threatChart.data.datasets[0].data = [
            localCount['DoS'], localCount['Probe'], localCount['R2L'], localCount['U2R']
        ];
        threatChart.update();

        // Update stats
        document.getElementById('totalBlocked').innerText = localBlocked;
        lastAlertCount = alerts.length;
    }

    // Increment analyzed counter
    totalAnalyzed += Math.floor(Math.random() * 8) + 1;
    document.getElementById('totalAnalyzed').innerText = totalAnalyzed.toLocaleString();
}

// Poll every 1.5 seconds
setInterval(() => {
    fetchAlerts();
    fetchBlocked();
}, 1500);

fetchAlerts();
fetchBlocked();
