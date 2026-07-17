import { useState } from 'react'
import { Finding, Severity, VulnIntel, AIAnalysis } from '../types'
import { ChevronDown, ChevronRight, FileCode2, AlertOctagon, AlertTriangle, AlertCircle, CheckCircle2, Wand2, Copy, Check, Shield, ExternalLink, Zap, BookOpen, Activity } from 'lucide-react'

interface Props {
  findings: Finding[]
  totalCount: number
}

const severityConfig: Record<Severity, { icon: typeof AlertOctagon; color: string; badge: string; glow: string }> = {
  critical: { icon: AlertOctagon, color: 'var(--color-critical)', badge: 'badge-critical', glow: 'glow-critical' },
  high: { icon: AlertTriangle, color: 'var(--color-high)', badge: 'badge-high', glow: 'glow-high' },
  medium: { icon: AlertCircle, color: 'var(--color-medium)', badge: 'badge-medium', glow: 'glow-medium' },
  low: { icon: CheckCircle2, color: 'var(--color-low)', badge: 'badge-low', glow: 'glow-low' }
}

function CopyButton({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className="hover-lift"
      style={{ padding: '6px', borderRadius: '8px', background: 'rgba(255,255,255,0.08)' }}
      title="Copy to clipboard"
    >
      {copied ? (
        <Check style={{ width: '16px', height: '16px', color: 'var(--color-success)' }} />
      ) : (
        <Copy style={{ width: '16px', height: '16px', color: 'var(--text-muted)' }} />
      )}
    </button>
  )
}

function CvssScoreRing({ score, severity }: { score: number; severity: string }) {
  const radius = 26
  const circumference = 2 * Math.PI * radius
  const progress = (score / 10) * circumference
  const strokeColor =
    severity === 'critical' ? '#ef4444' :
    severity === 'high' ? '#f97316' :
    severity === 'medium' ? '#eab308' : '#3b82f6'

  return (
    <div style={{ position: 'relative', width: '64px', height: '64px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg viewBox="0 0 64 64" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
        <circle cx="32" cy="32" r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" />
        <circle
          cx="32" cy="32" r={radius} fill="none"
          stroke={strokeColor} strokeWidth="4"
          strokeDasharray={`${progress} ${circumference}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
      </svg>
      <span style={{ color: strokeColor, fontWeight: 'bold', fontSize: '1.125rem', zIndex: 10 }}>{score}</span>
    </div>
  )
}

function ThreatIntelPanel({ intel }: { intel: VulnIntel }) {
  const [showIntel, setShowIntel] = useState(true)
  const flowNodes = intel.attack_surface.data_flow.split('→').map(s => s.trim())

  return (
    <div className="glass-card mt-4" style={{ borderColor: 'rgba(168, 85, 247, 0.2)', padding: '4px' }}>
      <div style={{ background: 'rgba(15, 15, 20, 0.8)', borderRadius: '12px', padding: '1.25rem' }}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div style={{ background: 'rgba(168, 85, 247, 0.2)', padding: '0.5rem', borderRadius: '8px' }}>
              <Shield style={{ width: '16px', height: '16px', color: '#c084fc' }} />
            </div>
            <div>
              <span style={{ fontSize: '0.875rem', fontWeight: 500, color: '#c084fc' }}>Threat Intelligence</span>
              <span style={{ fontSize: '0.75rem', color: 'rgba(168, 85, 247, 0.7)', marginLeft: '0.5rem' }}>Defensive Analysis</span>
            </div>
          </div>
          <button
            onClick={(e) => { e.stopPropagation(); setShowIntel(!showIntel) }}
            className="hover-lift"
            style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'transparent', border: 'none' }}
          >
            {showIntel ? 'Hide' : 'Show'}
          </button>
        </div>

        {showIntel && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div className="mb-2">
              <h5 className="flex items-center gap-2 mb-2" style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#c084fc' }}>
                <Zap style={{ width: '14px', height: '14px' }} />
                Risk Impact
              </h5>
              <div style={{ borderRadius: '12px', padding: '1rem', border: '1px solid rgba(239, 68, 68, 0.15)', background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(239, 68, 68, 0.02) 100%)' }}>
                <p style={{ fontSize: '0.875rem', color: '#e2e8f0', lineHeight: 1.6 }}>{intel.risk_impact}</p>
              </div>
            </div>

            <div className="mb-2">
              <h5 className="flex items-center gap-2 mb-2" style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#c084fc' }}>
                <Activity style={{ width: '14px', height: '14px' }} />
                CVSS Score & References
              </h5>
              <div className="flex flex-wrap gap-4 items-start">
                <div className="flex items-center gap-4">
                  <CvssScoreRing score={intel.cvss_score} severity={intel.cvss_severity} />
                  <div>
                    <p style={{ fontSize: '0.875rem', fontWeight: 'bold', textTransform: 'uppercase' }} className={`cvss-${intel.cvss_severity}`}>
                      {intel.cvss_severity}
                    </p>
                    <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: '0.25rem' }}>{intel.cvss_vector}</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 items-center">
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${intel.cwe_id.replace('CWE-', '')}.html`}
                    target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 px-4 py-2 hover-lift"
                    style={{ borderRadius: '8px', background: 'rgba(59, 130, 246, 0.1)', color: '#60a5fa', fontSize: '0.75rem', fontWeight: 500, border: '1px solid rgba(59, 130, 246, 0.2)', textDecoration: 'none' }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {intel.cwe_id}
                    <ExternalLink style={{ width: '12px', height: '12px' }} />
                  </a>
                  <a
                    href={intel.owasp_url}
                    target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 px-4 py-2 hover-lift"
                    style={{ borderRadius: '8px', background: 'rgba(249, 115, 22, 0.1)', color: '#fb923c', fontSize: '0.75rem', fontWeight: 500, border: '1px solid rgba(249, 115, 22, 0.2)', textDecoration: 'none' }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {intel.owasp_category}
                    <ExternalLink style={{ width: '12px', height: '12px' }} />
                  </a>
                </div>
              </div>
            </div>

            {intel.related_cves && intel.related_cves.length > 0 && (
              <div className="mb-2">
                <h5 className="flex items-center gap-2 mb-2" style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#c084fc' }}>
                  <BookOpen style={{ width: '14px', height: '14px' }} />
                  Real-World Incidents
                </h5>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {intel.related_cves.map((cve, i) => (
                    <a
                      key={i}
                      href={cve.url}
                      target="_blank" rel="noopener noreferrer"
                      className="flex items-start gap-4 p-4 hover-lift"
                      style={{ borderRadius: '8px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', textDecoration: 'none' }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', fontWeight: 'bold', color: '#c084fc', background: 'rgba(168, 85, 247, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>{cve.id}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <p style={{ fontSize: '0.875rem', color: '#e2e8f0', fontWeight: 500, margin: 0 }}>{cve.name}</p>
                        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px', margin: 0 }}>{cve.impact}</p>
                      </div>
                      <ExternalLink style={{ width: '14px', height: '14px', color: 'var(--text-muted)', marginTop: '4px' }} />
                    </a>
                  ))}
                </div>
              </div>
            )}

            <div className="mb-2">
              <h5 className="flex items-center gap-2 mb-2" style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-success)' }}>
                <CheckCircle2 style={{ width: '14px', height: '14px' }} />
                Remediation Steps
              </h5>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {intel.remediation_steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-4 p-4" style={{ borderRadius: '8px', background: 'rgba(255,255,255,0.02)' }}>
                    <span style={{ width: '24px', height: '24px', borderRadius: '50%', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', fontSize: '0.75rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>{i + 1}</span>
                    <p style={{ fontSize: '0.875rem', color: '#cbd5e1', lineHeight: 1.6, margin: 0 }}>{step}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="mb-2">
              <h5 className="flex items-center gap-2 mb-2" style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#fbbf24' }}>
                <AlertTriangle style={{ width: '14px', height: '14px' }} />
                Attack Surface
              </h5>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 500 }}>Data Flow</p>
                  <div className="flex items-center gap-2 flex-wrap">
                    {flowNodes.map((node, i) => (
                      <span key={i} style={{ display: 'contents' }}>
                        <span style={{ padding: '6px 12px', borderRadius: '8px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', fontSize: '0.75rem', color: '#cbd5e1', fontWeight: 500 }}>{node}</span>
                        {i < flowNodes.length - 1 && <span style={{ color: '#c084fc', fontSize: '1.125rem' }}>→</span>}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 500 }}>Entry Points</p>
                  <div className="flex flex-wrap gap-2">
                    {intel.attack_surface.entry_points.map((ep, i) => (
                      <span key={i} style={{ padding: '4px 10px', borderRadius: '9999px', fontSize: '0.75rem', fontWeight: 500, background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.2)' }}>{ep}</span>
                    ))}
                  </div>
                </div>
                <div className="glass-panel" style={{ borderRadius: '8px', padding: '0.75rem' }}>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: 500 }}>Trust Boundary</p>
                  <p style={{ fontSize: '0.875rem', color: '#cbd5e1' }}>{intel.attack_surface.trust_boundary}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function AiAnalysisPanel({ analysis }: { analysis: AIAnalysis }) {
  const [showAi, setShowAi] = useState(true)

  return (
    <div className="glass-card mt-4" style={{ borderColor: 'rgba(168, 85, 247, 0.2)', padding: '4px' }}>
      <div style={{ background: 'rgba(15, 15, 20, 0.8)', borderRadius: '12px', padding: '1rem' }}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div style={{ background: 'rgba(168, 85, 247, 0.2)', padding: '0.5rem', borderRadius: '8px', fontSize: '1.125rem' }}>
              {analysis.danger_emoji}
            </div>
            <div>
              <span style={{ fontSize: '0.875rem', fontWeight: 500, color: '#c084fc' }}>AI Threat Analysis</span>
              <span style={{ fontSize: '0.75rem', color: 'rgba(168, 85, 247, 0.7)', marginLeft: '0.5rem' }}>({analysis.danger_label})</span>
            </div>
          </div>
          <button
            onClick={(e) => { e.stopPropagation(); setShowAi(!showAi) }}
            className="hover-lift"
            style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'transparent', border: 'none' }}
          >
            {showAi ? 'Hide' : 'Show'}
          </button>
        </div>

        {showAi && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ background: 'rgba(168, 85, 247, 0.05)', border: '1px solid rgba(168, 85, 247, 0.1)', borderRadius: '8px', padding: '0.75rem' }}>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '0.5rem' }}>
                <span style={{ color: '#c084fc', fontWeight: 500 }}>Exploitation Summary: </span>
                {analysis.exploitation_summary}
              </p>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '0.5rem' }}>
                <span style={{ color: '#c084fc', fontWeight: 500 }}>Impact: </span>
                {analysis.impact_description}
              </p>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1' }}>
                <span style={{ color: '#c084fc', fontWeight: 500 }}>Fix Explanation: </span>
                {analysis.fix_explanation}
              </p>
            </div>

            <div>
              <h5 style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 500 }}>Prioritized Safeguards</h5>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {analysis.safeguard_steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 p-2" style={{ background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', padding: '2px 6px', borderRadius: '4px', flexShrink: 0,
                      background: step.priority === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                                  step.priority === 'high' ? 'rgba(249, 115, 22, 0.2)' :
                                  step.priority === 'medium' ? 'rgba(234, 179, 8, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                      color: step.priority === 'critical' ? '#f87171' :
                             step.priority === 'high' ? '#fb923c' :
                             step.priority === 'medium' ? '#facc15' : '#60a5fa'
                    }}>
                      {step.priority}
                    </span>
                    <span style={{ fontSize: '0.875rem', color: '#cbd5e1' }}>{step.step}</span>
                  </div>
                ))}
              </div>
            </div>

            {analysis.related_attacks && analysis.related_attacks.length > 0 && (
              <div>
                <h5 style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: 500 }}>Related Attacks</h5>
                <div className="flex flex-wrap gap-2">
                  {analysis.related_attacks.map((attack, i) => (
                    <span key={i} style={{ fontSize: '0.75rem', padding: '4px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: 'var(--text-muted)' }}>
                      {attack}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)
  const [showFix, setShowFix] = useState(true)
  const config = severityConfig[finding.severity as Severity] || severityConfig.low
  const Icon = config.icon

  return (
    <div style={{ borderBottom: '1px solid var(--border-glass)' }}>
      <div
        className="p-6 cursor-pointer group hover-lift"
        style={{ transition: 'background-color 0.2s', background: expanded ? 'rgba(255,255,255,0.02)' : 'transparent' }}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-4">
          <div className={`${config.badge} p-3 rounded-2xl ${config.glow}`} style={{ padding: '12px' }}>
            <Icon style={{ width: '24px', height: '24px' }} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2">
              <span style={{ fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', color: config.color }}>
                {finding.severity}
              </span>
              <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
              <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)', fontWeight: 500 }}>{finding.rule}</span>
              {finding.patch && (
                <>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
                  <span className="badge badge-success flex items-center gap-1">
                    <Wand2 style={{ width: '12px', height: '12px' }} />
                    Fix Available
                  </span>
                </>
              )}
              {finding.intel && (
                <>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '2px 8px', borderRadius: '9999px', background: 'rgba(168, 85, 247, 0.1)', color: '#c084fc', fontSize: '0.75rem', fontWeight: 500, border: '1px solid rgba(168, 85, 247, 0.2)' }}>
                    <Shield style={{ width: '12px', height: '12px' }} />
                    Intel
                  </span>
                </>
              )}
              {finding.ai_analysis && (
                <>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '2px 8px', borderRadius: '9999px', background: 'rgba(99, 102, 241, 0.1)', color: '#818cf8', fontSize: '0.75rem', fontWeight: 500, border: '1px solid rgba(99, 102, 241, 0.2)' }}>
                    <Wand2 style={{ width: '12px', height: '12px' }} />
                    AI Analyzed
                  </span>
                </>
              )}
            </div>

            <p style={{ color: '#e2e8f0', marginBottom: '0.5rem', lineHeight: 1.6 }}>{finding.message}</p>

            <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
              <div className="flex items-center gap-2">
                <FileCode2 style={{ width: '14px', height: '14px' }} />
                <span className="font-mono">{finding.file}:{finding.line}</span>
              </div>
              <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
              <span>Confidence: <span style={{ color: '#cbd5e1' }}>{finding.confidence}</span></span>
              {finding.intel && (
                <>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>•</span>
                  <span className={`font-medium cvss-${finding.intel.cvss_severity}`}>
                    CVSS {finding.intel.cvss_score}
                  </span>
                </>
              )}
            </div>
          </div>

          <div style={{ color: 'var(--text-muted)' }} className="transition-colors">
            {expanded ? (
              <ChevronDown style={{ width: '20px', height: '20px' }} />
            ) : (
              <ChevronRight style={{ width: '20px', height: '20px' }} />
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="px-6 pb-6 animate-fade-in">
          <div style={{ marginLeft: '4rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Vulnerable Code */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Vulnerable Code
                </h4>
                <CopyButton code={finding.snippet} />
              </div>
              <div className="glass-panel" style={{ borderRadius: '12px', overflow: 'hidden' }}>
                <pre style={{ padding: '1rem', fontSize: '0.875rem', color: '#cbd5e1', overflowX: 'auto' }}>
                  <code>{finding.snippet}</code>
                </pre>
              </div>
            </div>

            {/* Fix Section */}
            {finding.patch && (
              <div className="glass-card" style={{ borderColor: 'rgba(16, 185, 129, 0.2)', padding: '4px' }}>
                <div style={{ background: 'rgba(15, 15, 20, 0.8)', borderRadius: '12px', padding: '1rem' }}>
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div style={{ background: 'rgba(16, 185, 129, 0.2)', padding: '0.5rem', borderRadius: '8px' }}>
                        <Wand2 style={{ width: '16px', height: '16px', color: '#34d399' }} />
                      </div>
                      <div>
                        <span style={{ fontSize: '0.875rem', fontWeight: 500, color: '#34d399' }}>AI Suggested Fix</span>
                        <span style={{ fontSize: '0.75rem', color: 'rgba(16, 185, 129, 0.7)', marginLeft: '0.5rem' }}>({finding.patch.confidence} confidence)</span>
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setShowFix(!showFix)
                      }}
                      className="hover-lift"
                      style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'transparent', border: 'none' }}
                    >
                      {showFix ? 'Hide' : 'Show'}
                    </button>
                  </div>

                  {showFix && (
                    <>
                      <div className="flex items-center justify-between mb-2">
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Fixed Code</span>
                        <CopyButton code={finding.patch.fixed_code} />
                      </div>
                      <div className="glass-panel mb-4" style={{ borderRadius: '12px', overflow: 'hidden' }}>
                        <pre style={{ padding: '1rem', fontSize: '0.875rem', color: '#86efac', overflowX: 'auto' }}>
                          <code>{finding.patch.fixed_code}</code>
                        </pre>
                      </div>

                      <div style={{ background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.1)', borderRadius: '8px', padding: '0.75rem' }}>
                        <p style={{ fontSize: '0.875rem', color: '#cbd5e1' }}>
                          <span style={{ color: '#34d399', fontWeight: 500 }}>Why this works: </span>
                          {finding.patch.explanation}
                        </p>
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Threat Intelligence */}
            {finding.intel && (
              <ThreatIntelPanel intel={finding.intel} />
            )}

            {/* AI Analysis */}
            {finding.ai_analysis && (
              <AiAnalysisPanel analysis={finding.ai_analysis} />
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function FindingList({ findings, totalCount }: Props) {
  if (findings.length === 0) {
    return (
      <div className="p-12 text-center animate-fade-in">
        <div style={{ width: '64px', height: '64px', margin: '0 auto 1rem auto', borderRadius: '50%', background: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <CheckCircle2 style={{ width: '32px', height: '32px', color: 'var(--text-muted)' }} />
        </div>
        <p style={{ color: '#cbd5e1', marginBottom: '0.25rem', fontSize: '1.125rem' }}>No findings match the current filters</p>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>Try adjusting your filter criteria</p>
      </div>
    )
  }

  return (
    <div className="animate-fade-in">
      <div className="px-6 py-4 flex items-center justify-between border-b" style={{ background: 'rgba(255,255,255,0.02)' }}>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          Showing <span style={{ color: 'white', fontWeight: 500 }}>{findings.length}</span> of {' '}
          <span style={{ color: 'white', fontWeight: 500 }}>{totalCount}</span> findings
        </p>
        <div className="flex items-center gap-2">
          {findings.some(f => f.severity === 'critical') && (
            <span className="badge badge-critical glow-critical">Action Required</span>
          )}
        </div>
      </div>
      <div>
        {findings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </div>
  )
}
