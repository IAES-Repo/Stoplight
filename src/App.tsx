import { useState, useEffect } from 'react'
import './App.css'
import './index.css'

// Data models
export type Category = 'ingestion' | 'processing' | 'handling' | 'docker'

interface Service {
  id: string
  name: string
  port?: string
  category: Category
  description?: string
  dockerized?: boolean
  status?: 'up' | 'down'
  startup?: string[]
  logPath?: string
  configPath?: string
  docs?: string // documentation reference (now required for all entries we create)
  notes?: string
  site?: string // URL to web UI if applicable
}

interface HostNode {
  id: string
  name: string
  ip: string
  services: Service[]
  group?: string // e.g. FM-1 group label etc.
  notes?: string
}

// Example data approximating the provided diagram
const hosts: HostNode[] = [
  {
    id: 'crash',
    name: 'Crash',
    ip: '10.129.47.227',
    services: [
      { id: 'stoplight-chart', name: 'Stoplight Chart', category: 'handling', description: 'Web UI for the Stoplight infrastructure diagram (Vite dev server / static site).', status: 'up', startup: ['npm run dev'], docs: '/docs/stoplight.md', site: 'http://10.129.47.227:5173' }
    ],
    notes: 'Host serving the Stoplight UI.'
  },
  {
    id: 'fancybear',
    name: 'FancyBear',
    ip: '10.129.47.226',
    services: [
      { id: 'decap-script', name: 'Decap Script', category: 'ingestion', description: 'Decapsulates tunneled packets and prepares raw frames for processing.', status: 'up', startup: ['systemctl start decap-script'], logPath: '/var/log/decap.log', docs: '/docs/decap-script.md' },
      { id: 'sensor-software', name: 'Sensor Software', category: 'ingestion', description: 'Sensor agent that captures traffic and forwards to local processors.', status: 'up', startup: ['systemctl start sensor'], logPath: '/var/log/sensor.log', docs: '/docs/sensor-software.md' },
      { id: 'pre-processor', name: 'Pre Processor', category: 'processing', description: 'Cleans and enriches raw events before NDJSON conversion.', status: 'up', startup: ['systemctl start pre-processor'], configPath: '/etc/pre-processor/config.yml', docs: '/docs/pre-processor.md' },
      { id: 'json-to-ndjson', name: 'JSON to NDJSON', category: 'processing', description: 'Transforms JSON payloads into newline-delimited NDJSON for downstream consumers.', status: 'up', startup: ['python3 json2ndjson.py'], docs: '/docs/json-to-ndjson.md' },
      { id: 'box-monitor', name: 'Box Monitor', category: 'processing', description: 'Local watchdog that monitors processes, disk usage and custom sensors.', status: 'up', startup: ['systemctl start box-monitor'], logPath: '/var/log/box-monitor.log', docs: '/docs/box-monitor.md' },
      { id: 'zeek', name: 'Zeek', category: 'ingestion', description: 'Network security monitoring system extracting metadata from traffic.', status: 'up', startup: ['zeekctl deploy', 'zeekctl status'], logPath: '/opt/zeek/logs/current/', docs: 'https://docs.zeek.org/' },
      { id: 'suricata', name: 'Suricata', category: 'ingestion', description: 'IDS/IPS engine performing deep packet inspection.', status: 'up', startup: ['systemctl start suricata', 'suricata -T (config test)'], logPath: '/var/log/suricata/', configPath: '/etc/suricata/suricata.yaml', docs: 'https://docs.suricata.io/' },
      { id: 'packet-beats', name: 'Packet Beats', category: 'ingestion', description: 'Lightweight packet shipper that forwards traffic metadata to the pipeline.', status: 'up', startup: ['systemctl start packet-beats'], docs: '/docs/packet-beats.md' },
      { id: 'file-beats', name: 'File Beats', category: 'ingestion', description: 'Filebeat instance shipping logs and selected PCAP artifacts to central store.', status: 'up', startup: ['systemctl start filebeat'], docs: '/docs/file-beats.md' },
      { id: 'pcap-roll', name: 'PCAP Data Rollover', category: 'handling', description: 'Rotates PCAP capture files to NAS storage on a schedule and manages retention.', status: 'up', startup: ['cron handles rotation automatically'], notes: 'Monitor disk usage and retention policy.', docs: '/docs/pcap-rollover.md' }
    ],
    notes: 'Primary sensor & ingest host (renamed to FancyBear).'
  },
  {
    id: 'onix',
    name: 'Onix',
    ip: '10.129.47.225',
    services: [
      { id: 'logstash', name: 'Logstash', port: ':5601', category: 'processing', description: 'Pipelines events into Elasticsearch.', dockerized: true, status: 'up', startup: ['docker compose up -d logstash', 'Check logs for pipeline started'], configPath: '/docker/elk/logstash/pipeline.conf', docs: 'https://www.elastic.co/guide/en/logstash/current/index.html' },
      { id: 'elastic', name: 'Elastic', port: ':9200', category: 'handling', description: 'Data store & search engine.', dockerized: true, status: 'up', startup: ['docker compose up -d elasticsearch', 'curl :9200/_cluster/health'], docs: 'https://www.elastic.co/guide/' },
      { id: 'kibana', name: 'Kibana', port: ':443', category: 'handling', description: 'Visualization and exploration UI.', dockerized: true, status: 'down', startup: ['docker compose up -d kibana', 'Open UI to confirm'], docs: 'https://www.elastic.co/guide/en/kibana/current/index.html', site: 'https://kibana.internal/' }
    ],
    notes: 'Elastic stack core.'
  },
  {
    id: 'abra',
    name: 'Abra',
    ip: '10.129.47.230',
    services: [
      { id: 'glpi', name: 'GLPI', port: ':443', category: 'handling', description: 'ITSM / asset management.', status: 'up', startup: ['docker compose up -d glpi'], docs: 'https://glpi-project.org/', site: 'https://glpi.internal/' },
      { id: 'opencti', name: 'OpenCTI', port: ':8443', category: 'handling', description: 'Cyber threat intelligence platform.', dockerized: true, status: 'up', startup: ['docker compose up -d opencti', 'Check web UI'], docs: 'https://www.opencti.io/', site: 'https://opencti.internal:8443/' }
    ],
    notes: 'Management & intel host.'
  },
  {
    id: 'nas1',
    name: 'IAES-NAS-1',
    ip: '10.129.47.231',
    services: [
      { id: 'pcap-store', name: 'PCAP Storage', port: ':21', category: 'ingestion', description: 'Stores rolled over packet captures.', status: 'up', notes: 'FTP service restricted to local network.', docs: '/docs/pcap-storage.md' }
    ]
  },
  {
    id: 'nas2',
    name: 'IAES-NAS-2',
    ip: '10.129.47.232',
    services: [
      { id: 'db-store', name: 'Database Storage', port: ':21', category: 'handling', description: 'Persistent database volume storage.', status: 'up', notes: 'Mounted via NFS.', docs: '/docs/db-storage.md' }
    ]
  }
]

const categoryLabels: Record<Category, string> = {
  ingestion: 'Ingestion',
  processing: 'Processing',
  handling: 'Handling',
  docker: 'Docker'
}

const categoryColors: Record<Category, string> = {
  ingestion: 'var(--cat-ingestion)',
  processing: 'var(--cat-processing)',
  handling: 'var(--cat-handling)',
  docker: 'var(--cat-docker)'
}

interface DrawerState {
  host?: HostNode
  service?: Service
  open: boolean
}

interface StatusUpdate {
  id: string
  status: 'up' | 'down'
  timestamp: number
  host: string
  port: number
}

function App() {
  const [drawer, setDrawer] = useState<DrawerState>({ open: false })
  const [filter, setFilter] = useState<Category | 'all'>('all')
  const [serviceStatus, setServiceStatus] = useState<Record<string, 'up' | 'down'>>({})
  const [wsConnected, setWsConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<number>(0)

  // WebSocket connection for real-time status updates
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8081')
    
    ws.onopen = () => {
      console.log('Connected to health monitor')
      setWsConnected(true)
    }
    
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        if (message.type === 'status_update') {
          const newStatus: Record<string, 'up' | 'down'> = {}
          message.data.forEach((update: StatusUpdate) => {
            newStatus[update.id] = update.status
          })
          setServiceStatus(newStatus)
          setLastUpdate(message.timestamp)
          console.log('Status updated:', newStatus)
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }
    
    ws.onclose = () => {
      console.log('Disconnected from health monitor')
      setWsConnected(false)
    }
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      setWsConnected(false)
    }
    
    return () => {
      ws.close()
    }
  }, [])

  // Get current service status (real-time if available, fallback to static)
  const getServiceStatus = (service: Service): 'up' | 'down' => {
    return serviceStatus[service.id] || service.status || 'down'
  }

  const openHost = (host: HostNode) => {
    setDrawer({ host, service: undefined, open: true })
  }
  const openService = (host: HostNode, service: Service) => {
    setDrawer({ host, service, open: true })
  }
  const closeDrawer = () => setDrawer({ open: false })

  return (
    <div className="layout">
      <Header wsConnected={wsConnected} lastUpdate={lastUpdate} />
      <div className="legend">
        <span className="legend-title">Categories:</span>
        {(['all', 'ingestion', 'processing', 'handling', 'docker'] as const).map(c => (
          <button key={c} className={"legend-chip" + (filter === c ? ' active' : '')}
            style={c !== 'all' ? { ['--chip-color' as any]: categoryColors[c] } : {}}
            onClick={() => setFilter(c)}>{c === 'all' ? 'All' : categoryLabels[c]}</button>
        ))}
      </div>
      <div className="content-wrap">
        <main className="diagram-area" aria-label="Infrastructure diagram">
          {hosts.map(h => {
            const visible = h.services.filter(s =>
              filter === 'all' || s.category === filter || (filter === 'docker' && s.dockerized)
            )
            if (!visible.length) return null
            const normal = visible.filter(s => !s.dockerized)
            const dockerSubset = visible.filter(s => s.dockerized)
            return (
              <div key={h.id} className="host-card" tabIndex={0} role="group" aria-label={`${h.name} host`} onClick={() => openHost(h)} onKeyDown={e => { if (e.key === 'Enter') openHost(h) }}>
                <div className="host-header">
                  <h3>{h.name}</h3>
                  <span className="ip">{h.ip}</span>
                </div>
                <div className="services">
                  {normal.map(s => {
                    const currentStatus = getServiceStatus(s)
                    return (
                      <button key={s.id} className={"service" + (s.dockerized ? ' dockerized' : '')}
                        style={{ ['--service-color' as any]: categoryColors[s.category] }}
                        onClick={e => { e.stopPropagation(); openService(h, s) }}>
                        <span className={"status-icon " + currentStatus} aria-label={currentStatus === 'up' ? 'status up' : 'status down'}>{currentStatus === 'up' ? '✔' : '✖'}</span>
                        <span className="svc-row"><span className="svc-name">{s.name}</span>{s.port && <span className="port inline">{s.port}</span>}</span>
                      </button>
                    )
                  })}
                  {dockerSubset.length > 1 && h.id !== 'abra' && (
                    <div className="docker-group" aria-label={`Docker services (${dockerSubset.length})`} onClick={e => e.stopPropagation()}>
                      {dockerSubset.map(s => {
                        const currentStatus = getServiceStatus(s)
                        return (
                          <button key={s.id} className="service dockerized"
                            style={{ ['--service-color' as any]: categoryColors[s.category] }}
                            onClick={e => { e.stopPropagation(); openService(h, s) }}>
                            <span className={"status-icon " + currentStatus} aria-label={currentStatus === 'up' ? 'status up' : 'status down'}>{currentStatus === 'up' ? '✔' : '✖'}</span>
                            <span className="svc-row"><span className="svc-name">{s.name}</span>{s.port && <span className="port inline">{s.port}</span>}</span>
                          </button>
                        )
                      })}
                    </div>
                  )}
                  {(dockerSubset.length === 1 || h.id === 'abra') && dockerSubset.map(s => {
                    const currentStatus = getServiceStatus(s)
                    return (
                      <button key={s.id} className="service dockerized"
                        style={{ ['--service-color' as any]: categoryColors[s.category] }}
                        onClick={e => { e.stopPropagation(); openService(h, s) }}>
                        <span className={"status-icon " + currentStatus} aria-label={currentStatus === 'up' ? 'status up' : 'status down'}>{currentStatus === 'up' ? '✔' : '✖'}</span>
                        <span className="svc-row"><span className="svc-name">{s.name}</span>{s.port && <span className="port inline">{s.port}</span>}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            )
          })}
          {hosts.every(h => h.services.filter(s => (filter === 'all' || s.category === filter || (filter === 'docker' && s.dockerized))).length === 0) && (
            <p className="empty-msg" role="status">No services match current filter.</p>
          )}
        </main>
      </div>
      {drawer.open && (
        <aside className="drawer" aria-label="Details sidebar">
          <button className="close-btn" onClick={closeDrawer} aria-label="Close details">×</button>
          {drawer.host && !drawer.service && <HostDetails host={drawer.host} onOpenService={(s)=> setDrawer({ host: drawer.host, service: s, open: true })} getServiceStatus={getServiceStatus} />}
          {drawer.host && drawer.service && <ServiceDetails host={drawer.host} service={drawer.service} getServiceStatus={getServiceStatus} />}
        </aside>
      )}
    </div>
  )
}

function Header({ wsConnected, lastUpdate }: { wsConnected: boolean, lastUpdate: number }) {
  const formatLastUpdate = () => {
    if (!lastUpdate) return 'Never'
    const now = Date.now()
    const diff = now - lastUpdate
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
    return new Date(lastUpdate).toLocaleTimeString()
  }

  return (
    <header className="app-header">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div>
          <h1>IAES Stoplight Chart</h1>
          <p className="subtitle">Click a host or individual service for details.</p>
        </div>
        <div style={{ fontSize: '.65rem', color: 'var(--muted)', textAlign: 'right' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem' }}>
            <span style={{ 
              width: '8px', 
              height: '8px', 
              borderRadius: '50%', 
              backgroundColor: wsConnected ? '#48d176' : '#ff6b6b',
              display: 'inline-block'
            }}></span>
            {wsConnected ? 'Live monitoring' : 'Offline'}
          </div>
          <div>Last update: {formatLastUpdate()}</div>
        </div>
      </div>
    </header>
  )
}

const HostDetails = ({ host, onOpenService, getServiceStatus }: { host: HostNode, onOpenService: (s: Service)=>void, getServiceStatus: (s: Service) => 'up' | 'down' }) => (
  <div className="details">
    <h2>{host.name}</h2>
    <p className="muted">IP: {host.ip}</p>
    {host.notes && <p>{host.notes}</p>}
    <h3>Services</h3>
    <ul className="svc-list">
      {host.services.map(s => {
        const currentStatus = getServiceStatus(s)
        return (
          <li key={s.id}
            className={"svc-row-btn" + (s.dockerized ? ' docker' : '')}
            role="button"
            tabIndex={0}
            onClick={() => onOpenService(s)}
            onKeyDown={e => { if (e.key === 'Enter') onOpenService(s) }}
            style={{ ['--svc-color' as any]: categoryColors[s.category], borderLeftColor: s.dockerized ? 'var(--cat-docker)' : categoryColors[s.category] }}>
            <span className={"status-icon inline " + currentStatus} aria-label={currentStatus === 'up' ? 'status up' : 'status down'}>{currentStatus === 'up' ? '✔' : '✖'}</span>
            <strong>{s.name}</strong> {s.port} <em className="cat-label" style={{ color: categoryColors[s.category] }}>{categoryLabels[s.category]}</em>
            {s.dockerized && <span className="cat-label" style={{ color: 'var(--cat-docker)', marginLeft: '.35rem' }}>Docker</span>}
            {s.description && <p className="svc-desc">{s.description}</p>}
          </li>
        )
      })}
    </ul>
  </div>
)

const ServiceDetails = ({ host, service, getServiceStatus }: { host: HostNode, service: Service, getServiceStatus: (s: Service) => 'up' | 'down' }) => {
  const currentStatus = getServiceStatus(service)
  return (
    <div className="details">
      <h2>{service.name}</h2>
      <p className="muted">Host: {host.name} ({host.ip})</p>
      <p><strong>Status:</strong> <span className={currentStatus === 'up' ? 'status-chip up' : 'status-chip down'}>{currentStatus === 'up' ? '✔ Running' : '✖ Down'}</span></p>
      <p><strong>Category:</strong> <span style={{ color: categoryColors[service.category] }}>{categoryLabels[service.category]}</span>{service.dockerized && service.id.startsWith('docker-group-') ? <> (Group)</> : service.dockerized ? <> (Container)</> : null}</p>
      {service.description && (
      <div className="detail-section">
        <h3>Overview</h3>
        <p>{service.description}</p>
      </div>
      )}
      {service.startup && (
      <div className="detail-section">
        <h3>Startup Procedure</h3>
        <ol className="step-list">
          {service.startup.map((step,i)=>(<li key={i}>{step}</li>))}
        </ol>
      </div>
      )}
      {(service.configPath || service.logPath || service.notes) && (
      <div className="detail-section">
        <h3>Paths & Notes</h3>
        <ul className="kv-list">
          {service.configPath && <li><strong>Config:</strong> <code>{service.configPath}</code></li>}
            {service.logPath && <li><strong>Logs:</strong> <code>{service.logPath}</code></li>}
            {service.notes && <li><strong>Notes:</strong> {service.notes}</li>}
        </ul>
      </div>
      )}
      {service.site && (
      <div className="detail-section">
        <h3>Website</h3>
        <p><a href={service.site} target="_blank" rel="noreferrer">Open Site ↗</a></p>
      </div>
      )}
      {service.docs && (
      <div className="detail-section">
        <h3>Documentation</h3>
        <p><a href={service.docs} target="_blank" rel="noreferrer">Reference Docs ↗</a></p>
      </div>
      )}
      {service.id.startsWith('docker-group-') && (
      <>
        <h3>Included</h3>
        <ul className="svc-list">
          {host.services.filter(s => s.dockerized).map(s => (
            <li key={s.id} style={{ borderLeftColor: 'var(--cat-docker)' }}>
              <strong>{s.name}</strong> {s.port}
              {s.description && <p className="svc-desc">{s.description}</p>}
            </li>
          ))}
        </ul>
      </>
      )}
    </div>
  )
}

export default App
