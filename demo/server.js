/**
 * Armora Demo Server
 * 
 * This server provides a web interface to demonstrate the Armora bridge:
 * - Live packet viewer (hex dump)
 * - Chat demo (encrypted messages)
 * - File transfer
 * - Benchmark display
 * 
 * Run with: node server.js
 * Then open http://localhost:3000 in your browser
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { spawn } = require('child_process');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration
const PORT = process.env.PORT || 3000;
const BRIDGE_PATH = process.env.BRIDGE_PATH || '../build/armora-bridge';

// State
let bridgeProcess = null;
let clients = new Set();
let stats = {
    packetsEncrypted: 0,
    packetsDecrypted: 0,
    bytesEncrypted: 0,
    bytesDecrypted: 0,
    latencyMs: 0,
    startTime: null
};

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// API Routes
app.get('/api/status', (req, res) => {
    res.json({
        bridgeRunning: bridgeProcess !== null,
        stats: stats,
        uptime: stats.startTime ? Date.now() - stats.startTime : 0
    });
});

app.post('/api/start-bridge', (req, res) => {
    const { inputInterface, outputInterface, key } = req.body;
    
    if (bridgeProcess) {
        return res.status(400).json({ error: 'Bridge already running' });
    }
    
    // For demo, we'll simulate the bridge if not available
    if (process.env.DEMO_MODE === '1') {
        bridgeProcess = { simulated: true };
        stats.startTime = Date.now();
        startSimulation();
        return res.json({ success: true, simulated: true });
    }
    
    // Start actual bridge
    const args = [
        '-i', inputInterface || 'veth0',
        '-o', outputInterface || 'veth1',
        '-k', key || crypto.randomBytes(32).toString('hex'),
        '-s', '1'  // Stats every second
    ];
    
    try {
        bridgeProcess = spawn('sudo', [BRIDGE_PATH, ...args]);
        stats.startTime = Date.now();
        
        bridgeProcess.stdout.on('data', (data) => {
            const output = data.toString();
            parseStats(output);
            broadcast({ type: 'log', data: output });
        });
        
        bridgeProcess.stderr.on('data', (data) => {
            broadcast({ type: 'error', data: data.toString() });
        });
        
        bridgeProcess.on('close', (code) => {
            bridgeProcess = null;
            stats.startTime = null;
            broadcast({ type: 'bridgeStopped', code });
        });
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/stop-bridge', (req, res) => {
    if (!bridgeProcess) {
        return res.status(400).json({ error: 'Bridge not running' });
    }
    
    if (bridgeProcess.simulated) {
        stopSimulation();
        bridgeProcess = null;
        stats.startTime = null;
    } else {
        bridgeProcess.kill('SIGTERM');
    }
    
    res.json({ success: true });
});

// WebSocket handling
wss.on('connection', (ws) => {
    clients.add(ws);
    console.log('Client connected. Total:', clients.size);
    
    // Send current state
    ws.send(JSON.stringify({
        type: 'init',
        bridgeRunning: bridgeProcess !== null,
        stats: stats
    }));
    
    ws.on('message', (message) => {
        try {
            const msg = JSON.parse(message);
            handleClientMessage(ws, msg);
        } catch (e) {
            console.error('Invalid message:', e);
        }
    });
    
    ws.on('close', () => {
        clients.delete(ws);
        console.log('Client disconnected. Total:', clients.size);
    });
});

function broadcast(message) {
    const data = JSON.stringify(message);
    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

function handleClientMessage(ws, msg) {
    switch (msg.type) {
        case 'chat':
            // Simulate encryption/decryption for chat
            const encrypted = simulateEncrypt(msg.text);
            const decrypted = simulateDecrypt(encrypted);
            
            broadcast({
                type: 'chatMessage',
                original: msg.text,
                encrypted: encrypted,
                decrypted: decrypted,
                timestamp: Date.now()
            });
            break;
            
        case 'file':
            // Handle file transfer demo
            handleFileTransfer(ws, msg);
            break;
            
        case 'ping':
            // Latency measurement
            ws.send(JSON.stringify({ type: 'pong', timestamp: msg.timestamp }));
            break;
    }
}

// Parse stats from bridge output
function parseStats(output) {
    // Parse output like: "Enc: 1234 pkts (56789 B) | Dec: 1234 pkts (56789 B)"
    const encMatch = output.match(/Enc:\s*(\d+)\s*pkts\s*\((\d+)\s*B\)/);
    const decMatch = output.match(/Dec:\s*(\d+)\s*pkts\s*\((\d+)\s*B\)/);
    
    if (encMatch) {
        stats.packetsEncrypted = parseInt(encMatch[1]);
        stats.bytesEncrypted = parseInt(encMatch[2]);
    }
    if (decMatch) {
        stats.packetsDecrypted = parseInt(decMatch[1]);
        stats.bytesDecrypted = parseInt(decMatch[2]);
    }
    
    broadcast({ type: 'stats', stats: stats });
}

// Simulation for demo mode
let simulationInterval = null;

function startSimulation() {
    simulationInterval = setInterval(() => {
        // Simulate packet flow
        stats.packetsEncrypted += Math.floor(Math.random() * 100) + 50;
        stats.packetsDecrypted += Math.floor(Math.random() * 100) + 50;
        stats.bytesEncrypted += Math.floor(Math.random() * 150000) + 75000;
        stats.bytesDecrypted += Math.floor(Math.random() * 150000) + 75000;
        stats.latencyMs = Math.random() * 0.5 + 0.1;  // 0.1-0.6ms
        
        broadcast({ type: 'stats', stats: stats });
        
        // Simulate packet capture
        if (Math.random() > 0.7) {
            const packet = generateDemoPacket();
            broadcast({ type: 'packet', packet: packet });
        }
    }, 1000);
}

function stopSimulation() {
    if (simulationInterval) {
        clearInterval(simulationInterval);
        simulationInterval = null;
    }
}

function generateDemoPacket() {
    const size = Math.floor(Math.random() * 1400) + 64;
    const data = crypto.randomBytes(size);
    
    return {
        timestamp: Date.now(),
        size: size,
        direction: Math.random() > 0.5 ? 'encrypt' : 'decrypt',
        hexDump: data.slice(0, 64).toString('hex'),
        srcMac: 'AA:BB:CC:DD:EE:FF',
        dstMac: 'FF:EE:DD:CC:BB:AA',
        etherType: '0x0800'
    };
}

function simulateEncrypt(text) {
    // Simple demo encryption (not real crypto!)
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    
    return iv.toString('hex') + encrypted + tag;
}

function simulateDecrypt(encrypted) {
    // For demo, we just return a success indicator
    return '[Decrypted successfully]';
}

function handleFileTransfer(ws, msg) {
    // Simulate file encryption/transfer
    const fileSize = msg.size || 0;
    const chunks = Math.ceil(fileSize / 1400);
    
    let processed = 0;
    const interval = setInterval(() => {
        processed += Math.min(1400, fileSize - processed * 1400);
        const progress = Math.min(100, Math.floor((processed / fileSize) * 100));
        
        ws.send(JSON.stringify({
            type: 'fileProgress',
            filename: msg.filename,
            progress: progress,
            encrypted: true
        }));
        
        if (progress >= 100) {
            clearInterval(interval);
            ws.send(JSON.stringify({
                type: 'fileComplete',
                filename: msg.filename,
                size: fileSize
            }));
        }
    }, 50);
}

// Start server
server.listen(PORT, () => {
    console.log('');
    console.log('==========================================');
    console.log('  Armora Demo Server');
    console.log('==========================================');
    console.log('');
    console.log(`  Open http://localhost:${PORT} in your browser`);
    console.log('');
    console.log('  Environment variables:');
    console.log(`    PORT=${PORT}`);
    console.log(`    BRIDGE_PATH=${BRIDGE_PATH}`);
    console.log(`    DEMO_MODE=${process.env.DEMO_MODE || '0'} (set to 1 for simulation)`);
    console.log('');
});

