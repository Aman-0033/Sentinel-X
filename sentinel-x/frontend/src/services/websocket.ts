import { authStorage } from './auth';
import { DetectionItem, WebSocketTelemetryMessage } from '../types';

type Listener = (event: WebSocketTelemetryMessage) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private listeners: Set<Listener> = new Set();
  private isConnecting = false;
  private reconnectTimer: number | null = null;
  private simulatedFeedTimer: number | null = null;
  private status: 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED' = 'DISCONNECTED';

  public getStatus(): 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED' {
    return this.status;
  }

  public connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const token = authStorage.getToken();
    if (!token) {
      this.startSimulatedTelemetry();
      return;
    }

    this.isConnecting = true;
    this.status = 'CONNECTING';

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || 'localhost:5173';
    // Vite proxy directs /ws to backend:8000
    const wsUrl = `${protocol}//${host}/ws/dashboard?token=${encodeURIComponent(token)}`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.status = 'CONNECTED';
        this.isConnecting = false;
        this.stopSimulatedTelemetry();
        this.notify({
          event: 'CONNECTED',
          data: { message: 'Authenticated to Sentinel-X SOC Live Feed' },
        });
      };

      this.ws.onmessage = (event) => {
        try {
          const parsed: WebSocketTelemetryMessage = JSON.parse(event.data);
          this.notify(parsed);
        } catch (e) {
          console.error('[WebSocket] Failed to parse message', e);
        }
      };

      this.ws.onerror = () => {
        this.status = 'DISCONNECTED';
      };

      this.ws.onclose = () => {
        this.status = 'DISCONNECTED';
        this.isConnecting = false;
        this.ws = null;
        // Schedule reconnect & start simulated feed in meantime
        this.startSimulatedTelemetry();
        if (!this.reconnectTimer) {
          this.reconnectTimer = window.setTimeout(() => {
            this.reconnectTimer = null;
            this.connect();
          }, 8000);
        }
      };
    } catch {
      this.status = 'DISCONNECTED';
      this.startSimulatedTelemetry();
    }
  }

  public disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopSimulatedTelemetry();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.status = 'DISCONNECTED';
  }

  public subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(msg: WebSocketTelemetryMessage) {
    this.listeners.forEach((fn) => fn(msg));
  }

  /**
   * Generates realistic SOC network stream telemetry when backend WebSocket is offline
   */
  private startSimulatedTelemetry() {
    if (this.simulatedFeedTimer) return;

    const attackTypes = ['DDoS', 'PortScan', 'BruteForce', 'Botnet', 'Infiltration', 'SQLi', 'Benign'];
    const attackerIps = ['198.51.100.42', '203.0.113.88', '192.0.2.145', '45.33.32.156', '198.51.100.201'];
    const targetIps = ['10.0.1.50', '10.0.1.22', '10.0.1.10', '10.0.2.80', '10.0.1.15'];

    this.simulatedFeedTimer = window.setInterval(() => {
      const isAttack = Math.random() > 0.45;
      const attackType = isAttack
        ? attackTypes[Math.floor(Math.random() * (attackTypes.length - 1))]
        : 'Benign';

      const riskScore = isAttack ? Math.floor(Math.random() * 30 + 70) : Math.floor(Math.random() * 20);
      const severity =
        riskScore >= 90
          ? 'CRITICAL'
          : riskScore >= 70
          ? 'HIGH'
          : riskScore >= 40
          ? 'MEDIUM'
          : 'LOW';

      const fakeDetection: DetectionItem = {
        id: `sim-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        flow_id: `flow-${Math.floor(Math.random() * 90000 + 10000)}`,
        attack_type: attackType,
        confidence: Number((Math.random() * 0.15 + 0.84).toFixed(3)),
        anomaly_score: isAttack ? Number((Math.random() * 0.25 + 0.72).toFixed(3)) : 0.05,
        risk_score: riskScore,
        severity: isAttack ? severity : 'BENIGN',
        is_anomaly: isAttack && Math.random() > 0.5,
        detected_at: new Date().toISOString(),
        flow: {
          id: `flow-${Date.now()}`,
          source_ip: isAttack
            ? attackerIps[Math.floor(Math.random() * attackerIps.length)]
            : `192.168.1.${Math.floor(Math.random() * 100 + 10)}`,
          destination_ip: targetIps[Math.floor(Math.random() * targetIps.length)],
          source_port: Math.floor(Math.random() * 40000 + 10000),
          destination_port: [80, 443, 22, 3389, 445, 8080][Math.floor(Math.random() * 6)],
          protocol: Math.random() > 0.15 ? 'TCP' : 'UDP',
          packets: Math.floor(Math.random() * 5000 + 100),
          bytes: Math.floor(Math.random() * 500000 + 10000),
          duration_ms: Math.floor(Math.random() * 2000 + 50),
        },
      };

      this.notify({
        event: isAttack ? 'THREAT_DETECTED' : 'TELEMETRY_PULSE',
        data: {
          detection: fakeDetection,
          packet_rate: Math.floor(Math.random() * 45000 + 20000),
          traffic_rate_mbps: Number((Math.random() * 120 + 35).toFixed(1)),
          active_threats: 18 + Math.floor(Math.random() * 5),
          security_score: Math.max(75, 88 - (isAttack && severity === 'CRITICAL' ? 4 : 0)),
          timestamp: new Date().toISOString(),
        },
      });
    }, 3500);
  }

  private stopSimulatedTelemetry() {
    if (this.simulatedFeedTimer) {
      clearInterval(this.simulatedFeedTimer);
      this.simulatedFeedTimer = null;
    }
  }
}

export const wsService = new WebSocketService();
