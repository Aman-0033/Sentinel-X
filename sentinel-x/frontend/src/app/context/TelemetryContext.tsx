import React, { createContext, useContext, useEffect, useState } from 'react';
import { DetectionItem, WebSocketTelemetryMessage } from '../../types';
import { wsService } from '../../services/websocket';
import { mockDetections } from '../../services/mockData';

interface TelemetryContextType {
  wsStatus: 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED';
  liveFeed: DetectionItem[];
  packetRate: number;
  trafficRateMbps: number;
  activeThreatsCount: number;
  securityScore: number;
  activeCriticalAlert: DetectionItem | null;
  dismissCriticalAlert: () => void;
  isPaused: boolean;
  togglePause: () => void;
  clearFeed: () => void;
}

const TelemetryContext = createContext<TelemetryContextType | undefined>(undefined);

export const TelemetryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [wsStatus, setWsStatus] = useState<'CONNECTED' | 'CONNECTING' | 'DISCONNECTED'>('DISCONNECTED');
  const [liveFeed, setLiveFeed] = useState<DetectionItem[]>(mockDetections);
  const [packetRate, setPacketRate] = useState(38450);
  const [trafficRateMbps, setTrafficRateMbps] = useState(84.2);
  const [activeThreatsCount, setActiveThreatsCount] = useState(18);
  const [securityScore, setSecurityScore] = useState(84);
  const [activeCriticalAlert, setActiveCriticalAlert] = useState<DetectionItem | null>(null);
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    wsService.connect();

    const unsubscribe = wsService.subscribe((msg: WebSocketTelemetryMessage) => {
      setWsStatus(wsService.getStatus());

      if (msg.data.packet_rate) setPacketRate(msg.data.packet_rate);
      if (msg.data.traffic_rate_mbps) setTrafficRateMbps(msg.data.traffic_rate_mbps);
      if (msg.data.active_threats !== undefined) setActiveThreatsCount(msg.data.active_threats);
      if (msg.data.security_score !== undefined) setSecurityScore(msg.data.security_score);

      if (msg.data.detection) {
        const detection = msg.data.detection;

        // If it's a critical attack, trigger the top banner alert
        if (detection.severity === 'CRITICAL' && detection.attack_type !== 'Benign') {
          setActiveCriticalAlert(detection);
        }

        setLiveFeed((prev) => {
          if (isPaused) return prev;
          // Keep the newest 50 detections in memory
          return [detection, ...prev.slice(0, 49)];
        });
      }
    });

    return () => {
      unsubscribe();
    };
  }, [isPaused]);

  const dismissCriticalAlert = () => setActiveCriticalAlert(null);
  const togglePause = () => setIsPaused((prev) => !prev);
  const clearFeed = () => setLiveFeed([]);

  return (
    <TelemetryContext.Provider
      value={{
        wsStatus,
        liveFeed,
        packetRate,
        trafficRateMbps,
        activeThreatsCount,
        securityScore,
        activeCriticalAlert,
        dismissCriticalAlert,
        isPaused,
        togglePause,
        clearFeed,
      }}
    >
      {children}
    </TelemetryContext.Provider>
  );
};

export const useTelemetry = (): TelemetryContextType => {
  const context = useContext(TelemetryContext);
  if (!context) {
    throw new Error('useTelemetry must be used within a TelemetryProvider');
  }
  return context;
};
