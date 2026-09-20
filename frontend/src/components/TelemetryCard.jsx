import React from 'react';

/**
 * TelemetryCard — Reusable KPI card for the Security Dashboard.
 * Displays metric title, value, status color accent, optional subtitle, and icon.
 */
export default function TelemetryCard({
  title,
  value,
  subtitle,
  status = 'info', // 'safe' | 'warn' | 'danger' | 'info' | 'purple'
  icon,
  badge,
}) {
  return (
    <div className={`telemetry-card card-status-${status}`}>
      <div className="card-top">
        <span className="card-title">{title}</span>
        {icon && <span className="card-icon">{icon}</span>}
      </div>
      <div className="card-center">
        <span className={`card-value value-${status}`}>{value}</span>
        {badge && <span className={`card-badge badge-${status}`}>{badge}</span>}
      </div>
      {subtitle && <div className="card-subtitle">{subtitle}</div>}
      <div className={`card-glow-bar bar-${status}`} />
    </div>
  );
}
