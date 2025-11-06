# Real-time Health Monitoring Setup

This implements WebSocket-based real-time service monitoring for the Stoplight infrastructure dashboard.

## Quick Start

1. **Install health monitor dependencies:**
   ```bash
   cd /home/jordan/Documents/GitHun/library-of-scripts/Stoplight
   npm install --save-dev ws nodemon
   ```

2. **Start the health monitor:**
   ```bash
   node health-monitor.js
   ```
   Or for development with auto-restart:
   ```bash
   npx nodemon health-monitor.js
   ```

3. **Start the React app** (in another terminal):
   ```bash
   npm run dev
   ```

## How It Works

### Health Monitor (`health-monitor.js`)
- Runs on WebSocket port 8080
- Checks 14 services every 15 seconds
- Uses TCP socket tests for most services
- Uses HTTP requests for web services (Elastic, Kibana, etc.)
- Broadcasts status updates to all connected clients

### React App Updates
- Connects to WebSocket on startup
- Displays real-time status with live/offline indicator
- Shows last update timestamp
- Falls back to static status if WebSocket unavailable

### Service Check Types
- **TCP**: Simple socket connection test (ports 21, 3000, 4789, 5044, 5601, 47760, 50000)
- **HTTP/HTTPS**: GET request with status code validation (ports 80, 443, 5000, 8080, 8443, 9200)

## Configuration

Edit service configurations in `health-monitor.js`:

```javascript
const services = [
  { id: 'service-id', host: 'IP', port: PORT, type: 'tcp' },
  { id: 'web-service', host: 'IP', port: PORT, type: 'http', path: '/health' },
  // ...
]
```

## Monitoring

- Health monitor logs all checks to console
- WebSocket connection status shown in header
- Green dot = Live monitoring active
- Red dot = Offline (using static status)

## Production Notes

For production deployment:
1. Use PM2 or systemd for process management
2. Consider setting up nginx reverse proxy
3. Add authentication if needed
4. Monitor health-monitor process itself
5. Set up log rotation

## Troubleshooting

- **WebSocket connection failed**: Check health-monitor is running on port 8080
- **Services always showing down**: Verify network connectivity and port configurations
- **HTTPS certificate errors**: Monitor ignores self-signed certificate errors by default
