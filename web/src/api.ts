export type Scan = {
  id: string
  organization_id: string
  project_id: string
  profile: string
  model_id: string
  reserved_credits: number
  charged_credits: number
  state: string
  dynamic_authorized: boolean
  scope_note: string
  target_url: string | null
  created_at?: string
  progress?: AssessmentProgress
}

export type AssessmentProgress = {
  stage: 'queued' | 'source' | 'analysis' | 'report' | 'finalizing'
  health: 'healthy' | 'waiting' | 'delayed' | 'interrupted' | 'failed' | 'cancelled' | 'completed'
  message: string
  checked_at: string
  last_update_at: string
  last_activity_at: string
  last_signal_at: string | null
  deadline_at: string | null
  elapsed_seconds: number
  report_ready: boolean
}
export type LiveStatus = 'connecting' | 'connected' | 'reconnecting' | 'unavailable'

export type Finding = {
  id: string
  state: string
  source: string
  dependency: string
  advisory_id: string
  source_manifest: string
  scanner_version: string
  database_version: string
  scanner_output_sha256: string
  title: string | null
  severity: string | null
  explanation: string | null
  evidence_sha256: string[]
}

export type Report = { id: string; sha256: string; markdown: string }
export type ScanEvent = { kind: string; summary: string; sequence: number; created_at?: string }
export type ScanSummary = { id: string; state: string; profile: string; created_at: string }
export type Project = { id: string; name: string; organization_id: string }

export function scanPath(organizationId: string, scanId: string): string {
  return `/v1/organizations/${encodeURIComponent(organizationId)}/scans/${encodeURIComponent(scanId)}`
}

export async function api<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    signal: init.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000),
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
  })
  if (!response.ok) {
    const messages: Record<number, string> = {
      400: 'Check the assessment details and try again.',
      401: 'Your session has expired. Reconnect to your workspace.',
      402: 'There are not enough assessment credits available.',
      403: 'You do not have permission to perform this action.',
      404: 'This item could not be found or is no longer available.',
      409: 'This action is no longer available. Refresh the assessment and try again.',
      503: 'The assessment service is temporarily unavailable. Please try again later.',
    }
    throw new Error(messages[response.status] || 'The request could not be completed. Please try again.')
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export async function uploadZip(path: string, token: string, file: File): Promise<void> {
  const response = await fetch(path, {
    method: 'PUT', body: file,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/zip' },
  })
  if (!response.ok) throw new Error(`Upload failed (${response.status})`)
}

export async function followEvents(
  path: string,
  token: string,
  onEvent: (event: ScanEvent) => void,
  signal: AbortSignal,
  onStatus?: (status: LiveStatus) => void,
): Promise<void> {
  let lastId = 0
  while (!signal.aborted) {
    const stream = new AbortController()
    const cancel = () => stream.abort()
    signal.addEventListener('abort', cancel, { once: true })
    let idleTimer: ReturnType<typeof setTimeout> | undefined
    let reader: ReadableStreamDefaultReader<string> | undefined
    const touch = () => {
      clearTimeout(idleTimer)
      idleTimer = setTimeout(() => stream.abort(), 45000)
    }
    try {
      onStatus?.(lastId ? 'reconnecting' : 'connecting')
      touch()
      const response = await fetch(`${path}/events`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'text/event-stream',
          ...(lastId ? { 'Last-Event-ID': String(lastId) } : {}),
        },
        signal: stream.signal,
      })
      if ([401, 403, 404].includes(response.status)) {
        onStatus?.('unavailable')
        return
      }
      if (!response.ok || !response.body) throw new Error(`Event stream failed (${response.status})`)
      reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
      onStatus?.('connected')
      let buffer = ''
      while (!signal.aborted) {
        const { done, value } = await reader.read()
        if (done) break
        touch()
        buffer = (buffer + value).replace(/\r\n/g, '\n')
        if (buffer.length > 1024 * 1024) throw new Error('Event update exceeded its limit')
        let boundary = buffer.indexOf('\n\n')
        while (boundary >= 0) {
          if (signal.aborted) return
          const frame = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          const data = frame.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).replace(/^ /, '')).join('\n')
          if (data) {
            const event = JSON.parse(data) as ScanEvent
            if (Number.isSafeInteger(event.sequence) && event.sequence > lastId) {
              lastId = event.sequence
              onEvent(event)
            }
          }
          boundary = buffer.indexOf('\n\n')
        }
      }
    } catch {
      if (signal.aborted) return
    } finally {
      stream.abort()
      clearTimeout(idleTimer)
      signal.removeEventListener('abort', cancel)
      if (reader) {
        await reader.cancel().catch(() => undefined)
        reader.releaseLock()
      }
    }
    if (signal.aborted) return
    onStatus?.('reconnecting')
    await new Promise<void>(resolve => {
      const finish = () => { clearTimeout(timeout); signal.removeEventListener('abort', finish); resolve() }
      const timeout = setTimeout(finish, 2000)
      signal.addEventListener('abort', finish, { once: true })
      if (signal.aborted) finish()
    })
  }
}
