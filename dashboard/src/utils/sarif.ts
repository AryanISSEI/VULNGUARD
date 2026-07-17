import { ScanResults, Finding, Severity, Confidence, ScanSummary } from '../types'

export function isSarifFile(data: any): boolean {
  return data && data.$schema && typeof data.$schema === 'string' && data.$schema.includes('sarif')
}

export function parseSarif(sarifData: any): ScanResults {
  const findings: Finding[] = []
  const summary: ScanSummary = {
    total: 0,
    total_findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    patches_available: 0,
    duration_ms: 0,
    files_scanned: 0,
  }

  if (!sarifData.runs || !sarifData.runs[0] || !sarifData.runs[0].results) {
    return { findings, summary }
  }

  const run = sarifData.runs[0]
  
  // Extract properties if available
  if (run.properties) {
    summary.duration_ms = run.properties.durationMs || 0
    summary.files_scanned = run.properties.filesScanned || 0
  }

  for (let i = 0; i < run.results.length; i++) {
    const result = run.results[i]
    
    // Map SARIF level to our severity
    let severity: Severity = 'medium'
    if (result.level === 'error') {
      // In VulnGuard, we use High/Critical for errors. Let's default to high.
      severity = 'high'
      summary.high++
    } else if (result.level === 'warning') {
      severity = 'medium'
      summary.medium++
    } else if (result.level === 'note') {
      severity = 'low'
      summary.low++
    }

    // Map Locations
    let file = 'unknown'
    let line = 0
    if (result.locations && result.locations.length > 0) {
      const loc = result.locations[0].physicalLocation
      if (loc) {
        file = loc.artifactLocation?.uri || 'unknown'
        line = loc.region?.startLine || 0
      }
    }

    // Map Patches
    let patch = null
    if (result.fixes && result.fixes.length > 0) {
      const fix = result.fixes[0]
      const fixedCode = fix.artifactChanges?.[0]?.replacements?.[0]?.insertedContent?.text || ''
      patch = {
        description: fix.description?.text || 'Fix applied',
        fixed_code: fixedCode,
        explanation: 'Auto-generated patch from SARIF fix',
        confidence: 'high' as Confidence, // SARIF doesn't typically export our internal confidence enum cleanly
      }
      summary.patches_available++
    }

    // Generate finding ID
    const findingId = result.ruleId + '-' + i

    findings.push({
      id: findingId,
      rule: result.ruleId,
      severity,
      confidence: 'high', // SARIF spec doesn't natively map to our confidence, default high
      message: result.message?.text || 'No description provided',
      file,
      line,
      snippet: 'Snippet not available in SARIF',
      patch,
      intel: null,
      ai_analysis: null,
    })
  }

  summary.total = findings.length
  summary.total_findings = findings.length

  return { findings, summary }
}
