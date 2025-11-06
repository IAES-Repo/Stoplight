import WebSocket, { WebSocketServer } from 'ws';
import net from 'net';
import http from 'http';
import https from 'https';

const wss = new WebSocketServer({ port: 8081 });

// Service configurations for health checking
const services = [

  // FancyBear services
  { id: 'decap-script', host: '10.129.47.226', port: 9001, type: 'tcp' },
  { id: 'sensor-software', host: '10.129.47.226', port: 9101, type: 'tcp' },
  { id: 'pre-processor', host: '10.129.47.226', port: 9002, type: 'tcp' },
  { id: 'json-to-ndjson', host: '10.129.47.226', port: 50001, type: 'tcp' },
  { id: 'box-monitor', host: '10.129.47.226', port: 8085, type: 'http', path: '/status' },
  { id: 'zeek', host: '10.129.47.226', port: 47760, type: 'tcp' },
  { id: 'suricata', host: '10.129.47.226', port: 4789, type: 'tcp' },
  { id: 'packet-beats', host: '10.129.47.226', port: 5045, type: 'tcp' },
  { id: 'file-beats', host: '10.129.47.226', port: 5044, type: 'tcp' },
  { id: 'pcap-roll', host: '10.129.47.226', port: 22, type: 'tcp' },

  // Crash services
  { id: 'stoplight-chart', host: '10.129.47.227', port: 5173, type: 'http', path: '/' },

  // Onix services (ELK stack)
  { id: 'logstash', host: '10.129.47.225', port: 5601, type: 'tcp' },
  { id: 'elastic', host: '10.129.47.225', port: 9200, type: 'http', path: '/' },
  { id: 'kibana', host: '10.129.47.225', port: 443, type: 'http', path: '/' },

  // Abra services
  { id: 'glpi', host: '10.129.47.230', port: 443, type: 'http', path: '/' },
  { id: 'opencti', host: '10.129.47.230', port: 8443, type: 'http', path: '/health' },

  // NAS services
  { id: 'pcap-store', host: '10.129.47.231', port: 21, type: 'tcp' },
  { id: 'db-store', host: '10.129.47.232', port: 21, type: 'tcp' }
];

async function checkTcpService(service) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, 3000);
    
    socket.connect(service.port, service.host, () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve(true);
    });
    
    socket.on('error', () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve(false);
    });
  });
}

async function checkHttpService(service) {
  return new Promise((resolve) => {
    const options = {
      hostname: service.host,
      port: service.port,
      path: service.path || '/',
      method: 'GET',
      timeout: 3000,
      // Ignore SSL certificate errors for self-signed certs
      rejectUnauthorized: false
    };
    
    const protocol = service.port === 443 || service.port === 8443 ? https : http;
    
    const req = protocol.request(options, (res) => {
      // Consider 2xx, 3xx, and 401 status codes as "up"
      // 401 = Unauthorized but service is responding (like Elasticsearch)
      resolve(res.statusCode < 400 || res.statusCode === 401);
    });
    
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    
    req.setTimeout(3000);
    req.end();
  });
}

async function checkService(service) {
  try {
    if (service.type === 'http') {
      return await checkHttpService(service);
    } else {
      return await checkTcpService(service);
    }
  } catch (error) {
    console.error(`Error checking service ${service.id}:`, error.message);
    return false;
  }
}

async function monitorServices() {
  console.log(`[${new Date().toISOString()}] Checking ${services.length} services...`);
  
  const results = await Promise.all(
    services.map(async (service) => {
      const isUp = await checkService(service);
      const result = {
        id: service.id,
        status: isUp ? 'up' : 'down',
        timestamp: Date.now(),
        host: service.host,
        port: service.port
      };
      
      console.log(`  ${service.id}: ${result.status}`);
      return result;
    })
  );
  
  // Broadcast to all connected clients
  const message = JSON.stringify({
    type: 'status_update',
    data: results,
    timestamp: Date.now()
  });
  
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
  
  console.log(`Broadcasted status to ${wss.clients.size} clients\n`);
}

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('Client connected');
  
  // Send current status immediately upon connection
  monitorServices();
  
  ws.on('close', () => {
    console.log('Client disconnected');
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Start monitoring
console.log('Health Monitor starting...');
console.log(`WebSocket server listening on port 8081`);
console.log(`Monitoring ${services.length} services every 15 seconds\n`);

// Initial check
monitorServices();

// Schedule regular checks every 15 seconds
setInterval(monitorServices, 15000);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down health monitor...');
  wss.close(() => {
    console.log('WebSocket server closed');
    process.exit(0);
  });
});
