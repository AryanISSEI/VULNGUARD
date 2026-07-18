import { useState } from 'react'
import { Finding, Severity, VulnIntel, AIAnalysis } from '../types'
import { ChevronDown, ChevronRight, FileCode2, AlertOctagon, AlertTriangle, AlertCircle, CheckCircle2, Wand2, Copy, Check, Shield, ExternalLink, Zap, BookOpen, Activity } from 'lucide-react'

interface Props {
  findings: Finding[]
  totalCount: number
}

const severityConfig = {
  critical: { icon: AlertOctagon, color: 'text-red-400', badge: 'pro-badge-critical' },
  high: { icon: AlertTriangle, color: 'text-orange-400', badge: 'pro-badge-high' },
  medium: { icon: AlertCircle, color: 'text-yellow-400', badge: 'pro-badge-medium' },
  low: { icon: CheckCircle2, color: 'text-blue-400', badge: 'pro-badge-low' },
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
      className="p-1.5 rounded-lg bg-white/[0.08] hover:bg-white/[0.12] transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-4 h-4 text-green-400" />
      ) : (
        <Copy className="w-4 h-4 text-gray-400" />
      )}
    </button>
  )
}

/* ── CVSS Score Ring ── */
function CvssScoreRing({ score, severity }: { score: number; severity: string }) {
  const radius = 26
  const circumference = 2 * Math.PI * radius
  const progress = (score / 10) * circumference
  const colorClass = `cvss-${severity}`
  const strokeColor =
    severity === 'critical' ? '#ef4444' :
    severity === 'high' ? '#f97316' :
    severity === 'medium' ? '#eab308' : '#3b82f6'

  return (
    <div className="relative flex items-center justify-center w-16 h-16">
      <svg viewBox="0 0 64 64" className="w-full h-full transform -rotate-90">
        <circle cx="32" cy="32" r={radius} fill="none" stroke="var(--color-surface-hover)" strokeWidth="4" />
        <circle
          cx="32" cy="32" r={radius} fill="none"
          stroke={strokeColor} strokeWidth="4"
          strokeDasharray={`${progress} ${circumference}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
      </svg>
      <span className={`absolute font-bold text-sm ${colorClass}`}>{score}</span>
    </div>
  )
}

/* ── Threat Intel Panel ── */
function ThreatIntelPanel({ intel }: { intel: VulnIntel }) {
  const [showIntel, setShowIntel] = useState(true)
  const flowNodes = intel.attack_surface.data_flow.split('→').map(s => s.trim())

  return (
    <div className="border border-border rounded-xl mt-4 overflow-hidden bg-surface transition-all duration-300">
      <div className="bg-surface-hover p-4 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="bg-purple-500/10 p-2 rounded-lg text-lg">
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <div>
              <span className="text-sm font-medium text-purple-400">Threat Intelligence</span>
              <span className="text-xs text-purple-500/70 ml-2">Defensive Analysis</span>
            </div>
          </div>
          <button
            onClick={(e) => { e.stopPropagation(); setShowIntel(!showIntel) }}
            className="text-xs text-gray-400 hover:text-white transition-colors"
          >
            {showIntel ? 'Hide' : 'Show'}
          </button>
        </div>

        {showIntel && (
          <div className="p-4 space-y-6">
            {/* Risk Impact */}
            <div>
              <h5 className="flex items-center gap-2 text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">
                <Zap className="w-3.5 h-3.5" />
                Risk Impact
              </h5>
              <div className="bg-surface-hover/50 p-3 rounded-lg border border-border">
                <p className="text-sm text-gray-300 leading-relaxed">{intel.risk_impact}</p>
              </div>
            </div>

            {/* CVSS + References Row */}
            <div>
              <h5 className="flex items-center gap-2 text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">
                <Activity className="w-3.5 h-3.5" />
                CVSS Score & References
              </h5>
              <div className="flex flex-wrap gap-6 items-center">
                <div className="flex items-center gap-4">
                  <CvssScoreRing score={intel.cvss_score} severity={intel.cvss_severity} />
                  <div>
                    <p className={`text-sm font-bold uppercase cvss-${intel.cvss_severity}`}>
                      {intel.cvss_severity}
                    </p>
                    <p className="text-xs text-gray-500 font-mono mt-1">{intel.cvss_vector}</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 items-center">
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${intel.cwe_id.replace('CWE-', '')}.html`}
                    target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 text-xs font-medium border border-blue-500/20 hover:border-blue-500/40 transition-colors"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {intel.cwe_id}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                  <a
                    href={intel.owasp_url}
                    target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/10 text-orange-400 text-xs font-medium border border-orange-500/20 hover:border-orange-500/40 transition-colors"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {intel.owasp_category}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            </div>

            {/* Real-World CVEs */}
            {intel.related_cves && intel.related_cves.length > 0 && (
              <div>
                <h5 className="flex items-center gap-2 text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">
                  <BookOpen className="w-3.5 h-3.5" />
                  Real-World Incidents
                </h5>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {intel.related_cves.map((cve, i) => (
                    <a
                      key={i}
                      href={cve.url}
                      target="_blank" rel="noopener noreferrer"
                      className="bg-surface-hover border border-border hover:border-gray-500 p-3 rounded-lg flex items-start gap-3 transition-colors group"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span className="text-xs font-mono font-medium text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">{cve.id}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-300 font-medium truncate group-hover:text-gray-100">{cve.name}</p>
                        <p className="text-xs text-gray-500 mt-1 truncate">{cve.impact}</p>
                      </div>
                      <ExternalLink className="w-3.5 h-3.5 text-gray-500 group-hover:text-gray-300 flex-shrink-0 mt-0.5" />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation Steps */}
            <div>
              <h5 className="flex items-center gap-2 text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">
                <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                <span className="text-green-400">Remediation Steps</span>
              </h5>
              <div className="space-y-2">
                {intel.remediation_steps.map((step, i) => (
                  <div key={i} className="flex gap-3 bg-surface-hover/50 border border-border p-3 rounded-lg items-start">
                    <span className="w-5 h-5 flex items-center justify-center bg-surface border border-border rounded text-xs font-mono text-gray-400 flex-shrink-0">{i + 1}</span>
                    <p className="text-sm text-gray-300 leading-relaxed pt-0.5">{step}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Attack Surface */}
            <div>
              <h5 className="flex items-center gap-2 text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-amber-400">Attack Surface</span>
              </h5>
              <div className="space-y-4">
                {/* Data Flow */}
                <div>
                  <p className="text-xs text-gray-500 mb-2 font-medium">Data Flow</p>
                  <div className="flex flex-wrap items-center gap-2 bg-surface p-3 rounded-lg border border-border">
                    {flowNodes.map((node, i) => (
                      <span key={i} className="flex items-center gap-2">
                        <span className="px-2 py-1 bg-surface-hover text-gray-300 text-xs font-mono rounded border border-border">{node}</span>
                        {i < flowNodes.length - 1 && <span className="text-gray-500">→</span>}
                      </span>
                    ))}
                  </div>
                </div>
                {/* Entry Points */}
                <div>
                  <p className="text-xs text-gray-500 mb-2 font-medium">Entry Points</p>
                  <div className="flex flex-wrap gap-2">
                    {intel.attack_surface.entry_points.map((ep, i) => (
                      <span key={i} className="px-2 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium rounded">{ep}</span>
                    ))}
                  </div>
                </div>
                {/* Trust Boundary */}
                <div className="bg-surface-hover/50 rounded-lg p-3 border border-border">
                  <p className="text-xs text-gray-500 mb-1 font-medium">Trust Boundary</p>
                  <p className="text-sm text-gray-300">{intel.attack_surface.trust_boundary}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
  )
}

/* ── AI Analysis Panel ── */
function AiAnalysisPanel({ analysis }: { analysis: AIAnalysis }) {
  const [showAi, setShowAi] = useState(true)

  return (
    <div className="border border-border rounded-xl mt-4 overflow-hidden bg-surface transition-all duration-300">
      <div className="bg-surface-hover p-4 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="bg-purple-500/20 p-2 rounded-lg text-lg">
              {analysis.danger_emoji}
            </div>
            <div>
              <span className="text-sm font-medium text-purple-400">AI Threat Analysis</span>
              <span className="text-xs text-purple-500/70 ml-2">({analysis.danger_label})</span>
            </div>
          </div>
          <button
            onClick={() => setShowAi(!showAi)}
            className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              showAi 
                ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' 
                : 'bg-surface hover:bg-surface-hover text-gray-400 border border-border'
            }`}
          >
            {showAi ? 'Hide' : 'Show'}
          </button>
        </div>

        {showAi && (
          <div className="p-4 space-y-4">
            <div className="bg-purple-500/5 border border-purple-500/10 rounded-lg p-3">
              <p className="text-sm text-gray-300 mb-2">
                <span className="text-purple-400 font-medium">Exploitation Summary: </span>
                {analysis.exploitation_summary}
              </p>
              <p className="text-sm text-gray-300 mb-2">
                <span className="text-purple-400 font-medium">Impact: </span>
                {analysis.impact_description}
              </p>
              <p className="text-sm text-gray-300">
                <span className="text-purple-400 font-medium">Fix Explanation: </span>
                {analysis.fix_explanation}
              </p>
            </div>

            <div>
              <h5 className="text-xs text-gray-500 mb-2 font-medium">Prioritized Safeguards</h5>
              <div className="space-y-2">
                {analysis.safeguard_steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 bg-white/[0.02] p-2 rounded-lg border border-white/[0.05]">
                    <span className={`text-xs font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0 ${
                      step.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                      step.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      step.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      {step.priority}
                    </span>
                    <span className="text-sm text-gray-300">{step.step}</span>
                  </div>
                ))}
              </div>
            </div>

            {analysis.related_attacks && analysis.related_attacks.length > 0 && (
              <div>
                <h5 className="text-xs text-gray-500 mb-2 font-medium">Related Attacks</h5>
                <div className="flex flex-wrap gap-2">
                  {analysis.related_attacks.map((attack, i) => (
                    <span key={i} className="text-xs px-2 py-1 rounded bg-white/[0.05] border border-white/[0.1] text-gray-400">
                      {attack}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)
  const [showFix, setShowFix] = useState(true)
  const config = severityConfig[finding.severity as Severity] || severityConfig.low
  const Icon = config.icon

  return (
    <div className={`border-b border-border last:border-b-0 transition-colors ${expanded ? 'bg-surface-hover/80' : 'hover:bg-surface-hover/40'}`}>
      <div
        className="p-5 sm:p-6 cursor-pointer group"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-4">
          <div className={`pro-badge ${config.badge} shrink-0`}>
            <Icon className="w-4 h-4 shrink-0" />
            <span className="uppercase tracking-wider">{finding.severity}</span>
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-1.5">
              <span className="text-sm font-medium text-gray-200">{finding.rule}</span>
              {finding.patch && (
                <>
                  <span className="text-gray-600">•</span>
                  <span className="pro-badge pro-badge-success">
                    <Wand2 className="w-3 h-3" />
                    Patch Available
                  </span>
                </>
              )}
              {finding.intel && (
                <>
                  <span className="text-gray-600">•</span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 text-xs font-medium border border-purple-500/20">
                    <Shield className="w-3 h-3" />
                    Intel
                  </span>
                </>
              )}
              {finding.ai_analysis && (
                <>
                  <span className="text-gray-600">•</span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 text-xs font-medium border border-indigo-500/20">
                    <Wand2 className="w-3 h-3" />
                    AI Analyzed
                  </span>
                </>
              )}
            </div>

            <p className="text-gray-200 mb-2 leading-relaxed">{finding.message}</p>

            <div className="flex items-center gap-3 text-xs text-gray-500">
              <div className="flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5" />
                <span className="font-mono text-gray-400">{finding.file}:{finding.line}</span>
              </div>
              <span className="text-gray-600">•</span>
              <span>Confidence: <span className="text-gray-400">{finding.confidence}</span></span>
              {finding.intel && (
                <>
                  <span className="text-gray-600">•</span>
                  <span className={`font-medium cvss-${finding.intel.cvss_severity}`}>
                    CVSS {finding.intel.cvss_score}
                  </span>
                </>
              )}
            </div>
          </div>

          <div className="text-gray-500 group-hover:text-gray-300 transition-colors">
            {expanded ? (
              <ChevronDown className="w-5 h-5" />
            ) : (
              <ChevronRight className="w-5 h-5" />
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="px-5 pb-5">
          <div className="ml-14 space-y-4">
            {/* Vulnerable Code */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Vulnerable Code
                </h4>
                <CopyButton code={finding.snippet} />
              </div>
              <div className="glass-panel rounded-xl overflow-hidden">
                <pre className="p-4 text-sm text-gray-300 overflow-x-auto">
                  <code>{finding.snippet}</code>
                </pre>
              </div>
            </div>

            {/* Fix Section */}
            {finding.patch && (
              <div className="border border-border rounded-xl overflow-hidden">
                <div className="bg-surface p-4 border-b border-border flex items-center justify-between">
                  <div className="flex items-center gap-2 text-emerald-400 font-medium">
                    <Wand2 className="w-4 h-4" />
                    Recommended Patch
                  </div>
                  <button
                    onClick={() => setShowFix(!showFix)}
                    className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                      showFix 
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                        : 'bg-surface hover:bg-surface-hover text-gray-400 border border-border'
                    }`}
                  >
                    {showFix ? 'Hide' : 'Show'}
                  </button>
                </div>

                {showFix && (
                  <div className="p-4 bg-surface-hover/50">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-gray-500">Fixed Code</span>
                        <CopyButton code={finding.patch.fixed_code} />
                      </div>
                      <div className="glass-panel rounded-xl overflow-hidden mb-4">
                        <pre className="p-4 text-sm text-green-300 overflow-x-auto">
                          <code>{finding.patch.fixed_code}</code>
                        </pre>
                      </div>

                      <div className="bg-green-500/5 border border-green-500/10 rounded-lg p-3">
                        <p className="text-sm text-gray-300">
                          <span className="text-green-400 font-medium">Why this works: </span>
                          {finding.patch.explanation}
                        </p>
                      </div>
                  </div>
                )}
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
      <div className="p-12 text-center">
        <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/[0.05] flex items-center justify-center">
          <CheckCircle2 className="w-8 h-8 text-gray-500" />
        </div>
        <p className="text-gray-400 mb-1">No findings match the current filters</p>
        <p className="text-sm text-gray-500">Try adjusting your filter criteria</p>
      </div>
    )
  }

  return (
    <div>
      <div className="px-6 py-4 border-b border-white/[0.08] bg-white/[0.02] flex items-center justify-between">
        <p className="text-sm text-gray-400">
          Showing <span className="text-white font-medium">{findings.length}</span> of {' '}
          <span className="text-white font-medium">{totalCount}</span> findings
        </p>
        <div className="flex items-center gap-2">
          {findings.some(f => f.severity === 'critical') && (
            <span className="pro-badge pro-badge-critical animate-pulse">
              <AlertOctagon className="w-3.5 h-3.5" /> Action Required
            </span>
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
