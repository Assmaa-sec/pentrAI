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
}

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
export type ScanEvent = { kind: string; summary: string; sequence: number }
export type ScanSummary = { id: string; state: string; profile: string; created_at: string }
export type Project = { id: string; name: string; organization_id: string }

export function scanPath(organizationId: string, scanId: string): string {
  return `/v1/organizations/${encodeURIComponent(organizationId)}/scans/${encodeURIComponent(scanId)}`
}

export async function api<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
  })
  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`)
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
): Promise<void> {
  let lastId = 0
  while (!signal.aborted) {
    try {
      const response = await fetch(`${path}/events`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'text/event-stream',
          ...(lastId ? { 'Last-Event-ID': String(lastId) } : {}),
        },
        signal,
      })
      if (!response.ok || !response.body) throw new Error(`Event stream failed (${response.status})`)
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
      let buffer = ''
      while (!signal.aborted) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += value.replace(/\r\n/g, '\n')
        let boundary = buffer.indexOf('\n\n')
        while (boundary >= 0) {
          const frame = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          const data = frame.split('\n').filter(line => line.startsWith('data: ')).map(line => line.slice(6)).join('\n')
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
    }
    await new Promise<void>(resolve => {
      const timeout = window.setTimeout(resolve, 2000)
      signal.addEventListener('abort', () => { window.clearTimeout(timeout); resolve() }, { once: true })
    })
  }
}
