import type { LiveStatus, Scan } from './api'

export const ASSESSMENT_STAGES = [
  { id: 'queued', label: 'Waiting', description: 'Waiting for assessment capacity' },
  { id: 'source', label: 'Source review', description: 'Verifying and preparing your source' },
  { id: 'analysis', label: 'Analysis', description: 'Reviewing the approved scope' },
  { id: 'report', label: 'Report', description: 'Preparing findings and coverage details' },
  { id: 'finalizing', label: 'Final checks', description: 'Confirming the assessment has finished' },
] as const

const STATE_LABELS: Record<string, string> = {
  draft: 'Draft', uploaded: 'Uploaded', authorized: 'Waiting to start', queued: 'In progress',
  intake: 'Preparing source', static: 'Analyzing', dynamic_eligible: 'Analyzing',
  validating: 'Analyzing', reporting: 'Preparing report', cleanup: 'Finalizing',
  completed: 'Completed', failed: 'Could not complete', cancelled: 'Cancelled',
}

export function assessmentLabel(state: string): string {
  return STATE_LABELS[state] || 'Status unavailable'
}

export function isTerminal(state: string): boolean {
  return ['completed', 'failed', 'cancelled'].includes(state)
}

export function durationLabel(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return 'Not available'
  const whole = Math.floor(seconds)
  const hours = Math.floor(whole / 3600)
  const minutes = Math.floor((whole % 3600) / 60)
  if (hours) return `${hours}h ${minutes}m`
  if (minutes) return `${minutes}m ${whole % 60}s`
  return `${whole}s`
}

export function progressView(scan: Scan, live: LiveStatus, snapshotFailed: boolean) {
  const progress = scan.progress
  const terminal = isTerminal(scan.state)
  const stageIndex = ASSESSMENT_STAGES.findIndex(stage => stage.id === progress?.stage)
  const index = stageIndex >= 0 ? stageIndex : 0
  const phaseTitles = ['Waiting to start', 'Preparing your source', 'Analysis in progress',
    'Preparing your report', 'Final checks in progress']
  let title = phaseTitles[index]
  let tone = 'normal'
  let message = progress?.message || 'Waiting for a confirmed assessment update.'
  if (scan.state === 'completed') { title = 'Assessment completed'; tone = 'success' }
  else if (scan.state === 'failed') { title = 'Assessment could not complete'; tone = 'error' }
  else if (scan.state === 'cancelled') { title = 'Assessment cancelled'; tone = 'neutral' }
  else if (live === 'unavailable') {
    title = 'Workspace access needs attention'; tone = 'warning'
    message = 'Your access to this assessment could not be verified. Reconnect to your workspace, or ask your administrator to review your access.'
  }
  else if (snapshotFailed) {
    title = 'Assessment updates unavailable'; tone = 'warning'
    message = 'Your last confirmed status is shown below. We cannot confirm current progress. Check your connection; we will keep trying to reconnect.'
  } else if (progress?.health === 'interrupted') {
    title = 'Progress needs attention'; tone = 'warning'
  } else if (progress?.health === 'delayed') {
    title = 'Assessment updates are delayed'; tone = 'warning'
  } else if (live === 'reconnecting') {
    title = 'Live updates interrupted'; tone = 'warning'
    message = 'Reconnecting to live activity. The assessment status is checked separately every 10 seconds.'
  }
  return { index, title, tone, message, terminal, completed: scan.state === 'completed',
    connectionLabel: snapshotFailed && !terminal ? 'Connection unavailable'
      : terminal ? 'Final status recorded' : live === 'connected' ? 'Live activity connected'
      : live === 'connecting' ? 'Connecting to live activity' : 'Checking status independently' }
}
