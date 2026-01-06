/**
 * Armora Demo - Frontend Application
 */

// ============================================================================
// State
// ============================================================================

let ws = null;
let bridgeRunning = false;
let stats = {
    packetsEncrypted: 0,
    packetsDecrypted: 0,
    bytesEncrypted: 0,
    bytesDecrypted: 0,
    latencyMs: 0
};
let packets = [];
let benchmarkData = {
    latency: [],
    throughput: [],
    pps: []
};

// ============================================================================
// WebSocket Connection
// ============================================================================

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}`);
    
    ws.onopen = () => {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
    };
    
    ws.onclose = () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
        // Reconnect after 3 seconds
        setTimeout(connectWebSocket, 3000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleMessage(msg);
        } catch (e) {
            console.error('Failed to parse message:', e);
        }
    };
}

function handleMessage(msg) {
    switch (msg.type) {
        case 'init':
            bridgeRunning = msg.bridgeRunning;
            stats = msg.stats;
            updateUI();
            break;
            
        case 'stats':
            stats = msg.stats;
            updateStats();
            updateBenchmarks();
            break;
            
        case 'packet':
            addPacket(msg.packet);
            break;
            
        case 'log':
            addLog(msg.data, 'info');
            break;
            
        case 'error':
            addLog(msg.data, 'error');
            break;
            
        case 'bridgeStopped':
            bridgeRunning = false;
            updateBridgeStatus();
            addLog('Bridge stopped', 'info');
            break;
            
        case 'chatMessage':
            displayChatMessage(msg);
            break;
            
        case 'fileProgress':
            updateFileProgress(msg);
            break;
            
        case 'fileComplete':
            fileTransferComplete(msg);
            break;
            
        case 'pong':
            const latency = Date.now() - msg.timestamp;
            benchmarkData.latency.push(latency);
            if (benchmarkData.latency.length > 60) {
                benchmarkData.latency.shift();
            }
            break;
    }
}

function updateConnectionStatus(connected) {
    const indicator = document.getElementById('statusIndicator');
    const dot = indicator.querySelector('.status-dot');
    const text = indicator.querySelector('.status-text');
    
    if (connected) {
        dot.classList.add('connected');
        text.textContent = bridgeRunning ? 'Bridge Running' : 'Connected';
    } else {
        dot.classList.remove('connected');
        text.textContent = 'Disconnected';
    }
}

// ============================================================================
// Tab Navigation
// ============================================================================

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const tabId = tab.dataset.tab;
        
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Update tab content
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');
    });
});

// ============================================================================
// Bridge Control
// ============================================================================

async function startBridge() {
    const inputInterface = document.getElementById('inputInterface').value;
    const outputInterface = document.getElementById('outputInterface').value;
    const key = document.getElementById('pskKey').value;
    
    if (!key || key.length !== 64) {
        addLog('Please enter a valid 64-character hex key', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/start-bridge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ inputInterface, outputInterface, key })
        });
        
        const data = await response.json();
        
        if (data.success) {
            bridgeRunning = true;
            updateBridgeStatus();
            addLog('Bridge started successfully' + (data.simulated ? ' (simulation mode)' : ''), 'success');
        } else {
            addLog('Failed to start bridge: ' + data.error, 'error');
        }
    } catch (err) {
        addLog('Error: ' + err.message, 'error');
    }
}

async function stopBridge() {
    try {
        const response = await fetch('/api/stop-bridge', { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            bridgeRunning = false;
            updateBridgeStatus();
            addLog('Bridge stopped', 'info');
        }
    } catch (err) {
        addLog('Error: ' + err.message, 'error');
    }
}

function updateBridgeStatus() {
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const indicator = document.getElementById('statusIndicator');
    const text = indicator.querySelector('.status-text');
    
    startBtn.disabled = bridgeRunning;
    stopBtn.disabled = !bridgeRunning;
    text.textContent = bridgeRunning ? 'Bridge Running' : 'Connected';
}

function generateKey() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const hex = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('pskKey').value = hex;
}

// ============================================================================
// Stats Display
// ============================================================================

function updateStats() {
    document.getElementById('packetsEnc').textContent = formatNumber(stats.packetsEncrypted);
    document.getElementById('packetsDec').textContent = formatNumber(stats.packetsDecrypted);
    document.getElementById('bytesEnc').textContent = formatBytes(stats.bytesEncrypted);
    document.getElementById('bytesDec').textContent = formatBytes(stats.bytesDecrypted);
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatBytes(bytes) {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return bytes + ' B';
}

// ============================================================================
// Logging
// ============================================================================

function addLog(message, type = 'info') {
    const container = document.getElementById('logContainer');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    
    const timestamp = new Date().toLocaleTimeString();
    entry.textContent = `[${timestamp}] ${message}`;
    
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
    
    // Keep only last 100 entries
    while (container.children.length > 100) {
        container.removeChild(container.firstChild);
    }
}

// ============================================================================
// Packet Viewer
// ============================================================================

function addPacket(packet) {
    packets.push(packet);
    if (packets.length > 500) packets.shift();
    
    const list = document.getElementById('packetList');
    
    // Remove placeholder
    const placeholder = list.querySelector('.packet-placeholder');
    if (placeholder) placeholder.remove();
    
    const item = document.createElement('div');
    item.className = `packet-item ${packet.direction}`;
    
    item.innerHTML = `
        <div class="packet-meta">
            <span>${new Date(packet.timestamp).toLocaleTimeString()}</span>
            <span>${packet.direction.toUpperCase()}</span>
            <span>${packet.size} bytes</span>
            <span>${packet.srcMac} → ${packet.dstMac}</span>
        </div>
        <div class="packet-hex">${packet.hexDump}</div>
    `;
    
    list.appendChild(item);
    
    // Auto-scroll if enabled
    if (document.getElementById('autoscroll').checked) {
        list.scrollTop = list.scrollHeight;
    }
    
    // Keep only last 200 packets in DOM
    while (list.children.length > 200) {
        list.removeChild(list.firstChild);
    }
}

function clearPackets() {
    const list = document.getElementById('packetList');
    list.innerHTML = '<div class="packet-placeholder">Start the bridge to see live packets...</div>';
    packets = [];
}

// ============================================================================
// Chat Demo
// ============================================================================

function sendChat() {
    const input = document.getElementById('chatInput');
    const text = input.value.trim();
    
    if (!text) return;
    
    // Add to sender side
    addChatMessage('senderMessages', text, 'sent');
    
    // Send via WebSocket
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'chat', text }));
    } else {
        // Simulate locally
        simulateChat(text);
    }
    
    input.value = '';
}

function simulateChat(text) {
    // Simulate encryption
    const encrypted = simulateEncryption(text);
    addChatMessage('encryptedMessages', encrypted, 'encrypted');
    
    // Simulate decryption after delay
    setTimeout(() => {
        addChatMessage('receiverMessages', text, 'received');
    }, 300);
}

function simulateEncryption(text) {
    // Create a fake "encrypted" hex string
    const bytes = new TextEncoder().encode(text);
    const iv = Array.from(crypto.getRandomValues(new Uint8Array(12)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    const data = Array.from(bytes)
        .map(b => (b ^ 0x42).toString(16).padStart(2, '0')).join('');
    const tag = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    return iv + data + tag;
}

function displayChatMessage(msg) {
    addChatMessage('senderMessages', msg.original, 'sent');
    addChatMessage('encryptedMessages', msg.encrypted, 'encrypted');
    setTimeout(() => {
        addChatMessage('receiverMessages', msg.original, 'received');
    }, 100);
}

function addChatMessage(containerId, text, type) {
    const container = document.getElementById(containerId);
    const msg = document.createElement('div');
    msg.className = `chat-message ${type}`;
    msg.textContent = text;
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
}

// ============================================================================
// File Transfer
// ============================================================================

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = formatBytes(file.size);
    document.getElementById('fileProgress').style.display = 'block';
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressText').textContent = '0%';
    
    // Send file info
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'file',
            filename: file.name,
            size: file.size
        }));
    } else {
        // Simulate file transfer
        simulateFileTransfer(file);
    }
}

function simulateFileTransfer(file) {
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 15 + 5;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            fileTransferComplete({ filename: file.name, size: file.size });
        }
        updateFileProgress({ progress: Math.floor(progress) });
    }, 100);
}

function updateFileProgress(msg) {
    document.getElementById('progressFill').style.width = msg.progress + '%';
    document.getElementById('progressText').textContent = msg.progress + '% (encrypted)';
}

function fileTransferComplete(msg) {
    document.getElementById('progressText').textContent = '100% - Complete!';
    
    // Add to history
    const history = document.getElementById('historyList');
    const item = document.createElement('div');
    item.className = 'history-item';
    item.innerHTML = `
        <span>${msg.filename} (${formatBytes(msg.size)})</span>
        <span class="status">✓ Encrypted & Transferred</span>
    `;
    history.insertBefore(item, history.firstChild);
    
    // Reset after delay
    setTimeout(() => {
        document.getElementById('fileProgress').style.display = 'none';
        document.getElementById('fileInput').value = '';
    }, 2000);
}

// ============================================================================
// Benchmarks
// ============================================================================

function updateBenchmarks() {
    // Calculate metrics
    const latency = stats.latencyMs || 0;
    const bytesPerSec = stats.bytesEncrypted / ((Date.now() - (stats.startTime || Date.now())) / 1000) || 0;
    const throughputMbps = (bytesPerSec * 8) / 1000000;
    const pps = stats.packetsEncrypted / ((Date.now() - (stats.startTime || Date.now())) / 1000) || 0;
    
    document.getElementById('latencyValue').textContent = latency.toFixed(2);
    document.getElementById('throughputValue').textContent = throughputMbps.toFixed(1);
    document.getElementById('ppsValue').textContent = formatNumber(Math.floor(pps));
    
    // Store for charts
    benchmarkData.throughput.push(throughputMbps);
    benchmarkData.pps.push(pps);
    
    if (benchmarkData.throughput.length > 60) {
        benchmarkData.throughput.shift();
        benchmarkData.pps.shift();
    }
    
    // Update mini charts
    drawMiniChart('latencyChart', benchmarkData.latency, '#00ff88');
    drawMiniChart('throughputChart', benchmarkData.throughput, '#00ccff');
    drawMiniChart('ppsChart', benchmarkData.pps, '#ffaa00');
}

function drawMiniChart(elementId, data, color) {
    const container = document.getElementById(elementId);
    if (!data.length) return;
    
    const max = Math.max(...data) || 1;
    const width = container.offsetWidth;
    const height = container.offsetHeight;
    
    let svg = container.querySelector('svg');
    if (!svg) {
        svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('width', '100%');
        svg.setAttribute('height', '100%');
        svg.style.display = 'block';
        container.appendChild(svg);
    }
    
    const points = data.map((v, i) => {
        const x = (i / (data.length - 1 || 1)) * width;
        const y = height - (v / max) * height;
        return `${x},${y}`;
    }).join(' ');
    
    svg.innerHTML = `
        <polyline
            fill="none"
            stroke="${color}"
            stroke-width="2"
            points="${points}"
        />
    `;
}

function runBenchmark() {
    addLog('Starting benchmark...', 'info');
    
    // Reset data
    benchmarkData = { latency: [], throughput: [], pps: [] };
    
    // Start ping measurements
    const pingInterval = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
        }
    }, 100);
    
    // Run for 10 seconds
    setTimeout(() => {
        clearInterval(pingInterval);
        showBenchmarkResults();
    }, 10000);
}

function showBenchmarkResults() {
    const results = document.getElementById('benchmarkResults');
    const tbody = document.getElementById('resultsBody');
    
    const avgLatency = benchmarkData.latency.length 
        ? benchmarkData.latency.reduce((a, b) => a + b) / benchmarkData.latency.length 
        : 0;
    const avgThroughput = benchmarkData.throughput.length
        ? benchmarkData.throughput.reduce((a, b) => a + b) / benchmarkData.throughput.length
        : 0;
    const avgPps = benchmarkData.pps.length
        ? benchmarkData.pps.reduce((a, b) => a + b) / benchmarkData.pps.length
        : 0;
    
    const metrics = [
        { name: 'Latency', value: avgLatency.toFixed(2) + ' ms', target: '< 1 ms', pass: avgLatency < 1 },
        { name: 'Throughput', value: avgThroughput.toFixed(1) + ' Mbps', target: '> 100 Mbps', pass: avgThroughput > 100 },
        { name: 'Packets/sec', value: formatNumber(Math.floor(avgPps)), target: '> 10K pps', pass: avgPps > 10000 },
    ];
    
    tbody.innerHTML = metrics.map(m => `
        <tr>
            <td>${m.name}</td>
            <td>${m.value}</td>
            <td>${m.target}</td>
            <td class="${m.pass ? 'pass' : 'fail'}">${m.pass ? '✓ PASS' : '✗ FAIL'}</td>
        </tr>
    `).join('');
    
    results.style.display = 'block';
    addLog('Benchmark complete', 'success');
}

// ============================================================================
// UI Updates
// ============================================================================

function updateUI() {
    updateStats();
    updateBridgeStatus();
    updateConnectionStatus(true);
}

// ============================================================================
// Initialize
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    
    // Periodic stats update
    setInterval(() => {
        if (bridgeRunning) {
            updateBenchmarks();
        }
    }, 1000);
});

