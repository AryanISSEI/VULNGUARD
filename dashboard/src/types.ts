export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Confidence = 'high' | 'medium' | 'low'

export interface Patch {
  description: string
  fixed_code: string
  explanation: string
  confidence: Confidence
}

export interface RelatedCVE {
  id: string
  name: string
  impact: string
  url: string
}

export interface AttackSurface {
  entry_points: string[]
  data_flow: string
  trust_boundary: string
  exposure_level: 'critical' | 'high' | 'medium' | 'low'
}

export interface VulnIntel {
  risk_impact: string
  cvss_score: number
  cvss_vector: string
  cvss_severity: string
  cwe_id: string
  cwe_name: string
  owasp_category: string
  owasp_url: string
  related_cves: RelatedCVE[]
  remediation_steps: string[]
  attack_surface: AttackSurface
}

export interface SafeguardStep {
  step: string
  priority: string
}

export interface AIAnalysis {
  danger_rating: number
  danger_label: string
  danger_emoji: string
  danger_color: string
  exploitation_summary: string
  impact_description: string
  fix_explanation: string
  safeguard_steps: SafeguardStep[]
  related_attacks: string[]
}

export interface Finding {
  id: string
  rule: string
  severity: Severity
  confidence: Confidence
  message: string
  file: string
  line: number
  snippet: string
  patch: Patch | null
  intel: VulnIntel | null
  ai_analysis: AIAnalysis | null
}

export interface ScanSummary {
  total: number
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  patches_available: number
  duration_ms: number
  files_scanned: number
}

export interface ScanResults {
  findings: Finding[]
  summary: ScanSummary
}

export interface FilterOptions {
  severity?: Severity[]
  rule?: string[]
  hasPatch?: boolean | null
}
