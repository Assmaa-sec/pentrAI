import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, followEvents, scanPath, uploadZip, type Finding, type Project, type Report, type Scan, type ScanEvent, type ScanSummary } from './api'

type Connection = { organizationId: string; scanId: string; token: string }
type WorkspaceView = 'overview' | 'projects' | 'assessments' | 'findings' | 'administration'
type Member = { id: string; user_id: string; identity: string; role: string }
type AuditEntry = { id: string; action: string; created_at: string }
type AssessmentAuthorization = { active: boolean; id?: string; scope_statement?: string; source_allowed?: boolean; url_allowed?: boolean; expires_at?: string; terms_version?: string }
type CreditBalance = { available: number; reserved: number; spent: number }
type ModelOption = { id: string; label: string; prompt_credit_rate: number; completion_credit_rate: number }
type WorkspaceSummary = { projects: number; assessments: number; completed: number; findings: number }
type OrganizationScan = ScanSummary & { project_id: string; project_name: string }
type OrganizationFinding = Pick<Finding, 'id' | 'state' | 'source' | 'dependency' | 'advisory_id' | 'source_manifest' | 'title' | 'severity'> & { scan_id: string; project_id: string; project_name: string; created_at: string }

const priorEventLabels: Record<string, string> = {
  'Static scan authorized': 'Assessment accepted',
  'Static scan queued': 'Assessment queued',
  'Source digest verified': 'Source archive verified',
  'Static dependency analysis completed': 'Dependency analysis completed',
  'Static report persisted': 'Assessment report ready',
  'Static scan completed': 'Assessment completed',
  'Static scan cancelled before processing': 'Assessment cancelled',
  'Static scan retry authorized': 'Assessment retry accepted',
  'Worker lost; retry is available': 'Assessment interrupted. Retry is available',
  'Static worker failed': 'Assessment could not be completed',
}

export default function App() {
  const [organizationId, setOrganizationId] = useState('')
  const [projectId, setProjectId] = useState('')
  const [projectName, setProjectName] = useState('')
  const [projects, setProjects] = useState<Project[]>([])
  const [accessRole, setAccessRole] = useState('')
  const [accessUserId, setAccessUserId] = useState('')
  const [members, setMembers] = useState<Member[]>([])
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([])
  const [removeMemberId, setRemoveMemberId] = useState('')
  const [token, setToken] = useState('')
  const [sourceFile, setSourceFile] = useState<File | null>(null)
  const [targetUrl, setTargetUrl] = useState('')
  const [webScansAvailable, setWebScansAvailable] = useState(false)
  const [sourceScansAvailable, setSourceScansAvailable] = useState(false)
  const [sourceMode, setSourceMode] = useState('hexstrike')
  const [assessmentAuthorization, setAssessmentAuthorization] = useState<AssessmentAuthorization>({ active: false })
  const [creditBalance, setCreditBalance] = useState<CreditBalance | null>(null)
  const [modelOptions, setModelOptions] = useState<ModelOption[]>([])
  const [modelId, setModelId] = useState('managed')
  const [authorizationScope, setAuthorizationScope] = useState('')
  const [authorizationSource, setAuthorizationSource] = useState(true)
  const [authorizationUrl, setAuthorizationUrl] = useState(false)
  const [authorizationDays, setAuthorizationDays] = useState(30)
  const [authorizationTermsAccepted, setAuthorizationTermsAccepted] = useState(false)
  const [webProof, setWebProof] = useState<{ id: string; token: string; verification_url: string; targetUrl: string; projectId: string; organizationId: string; verified: boolean } | null>(null)
  const [assessmentProfile, setAssessmentProfile] = useState<'quick' | 'standard' | 'deep'>('standard')
  const [scopeNote, setScopeNote] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [recentScans, setRecentScans] = useState<ScanSummary[]>([])
  const [organizationScans, setOrganizationScans] = useState<OrganizationScan[]>([])
  const [organizationFindings, setOrganizationFindings] = useState<OrganizationFinding[]>([])
  const [workspaceSummary, setWorkspaceSummary] = useState<WorkspaceSummary | null>(null)
  const [sessionChecking, setSessionChecking] = useState(true)
  const [connection, setConnection] = useState<Connection | null>(null)
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [report, setReport] = useState<Report | null>(null)
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [error, setError] = useState('')
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState('')
  const [busy, setBusy] = useState(false)
  const [accessOpen, setAccessOpen] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [view, setView] = useState<WorkspaceView>('overview')
  const [findingQuery, setFindingQuery] = useState('')
  const [scanQuery, setScanQuery] = useState('')
  const [scanProjectFilter, setScanProjectFilter] = useState('all')
  const [findingSource, setFindingSource] = useState('all')
  const [showReportText, setShowReportText] = useState(false)
  const projectRequest = useRef<{ signature: string; key: string } | null>(null)
  const cancelRequest = useRef<{ scanId: string; key: string } | null>(null)
  const localSessionRequested = useRef(false)
  const webTargetReady = !targetUrl.trim() || !!(webProof?.verified && webProof.targetUrl === targetUrl.trim() && webProof.projectId === projectId && webProof.organizationId === organizationId.trim())

  function disconnectWorkspace() {
    setAccessRole('')
    setAccessUserId('')
    setProjects([])
    setProjectId('')
    setRecentScans([])
    setOrganizationScans([])
    setOrganizationFindings([])
    setWorkspaceSummary(null)
    setConnection(null)
    setScan(null)
    setFindings([])
    setReport(null)
    setEvents([])
    setMembers([])
    setAuditEntries([])
    setView('overview')
    setShowCreate(false)
    setWebProof(null)
    setAssessmentAuthorization({ active: false })
    setCreditBalance(null)
  }

  useEffect(() => {
    void fetch('/v1/capabilities', { cache: 'no-store' })
      .then(response => response.ok ? response.json() as Promise<{ source_scans_available: boolean; web_scans_available: boolean; source_mode: string }> : null)
      .then(value => {
        setWebScansAvailable(value?.web_scans_available === true)
        setSourceScansAvailable(value?.source_scans_available === true)
        setSourceMode(value?.source_mode || 'hexstrike')
      })
      .catch(() => {
        setWebScansAvailable(false)
        setSourceScansAvailable(false)
      })
  }, [])

  useEffect(() => {
    if (localSessionRequested.current) return
    localSessionRequested.current = true
    void fetch('/v1/local/session', { method: 'POST', cache: 'no-store' })
      .then(async response => {
        if (!response.ok) return
        const local = await response.json() as { organization_id: string; token: string }
        await refreshProjects(undefined, { organizationId: local.organization_id, token: local.token })
      })
      .catch(() => undefined)
      .finally(() => setSessionChecking(false))
  }, [])

  useEffect(() => {
    if (view === 'assessments' && showCreate) {
      document.getElementById('new-assessment')?.scrollIntoView({ block: 'start' })
    }
  }, [view, showCreate])

  useEffect(() => {
    if (!connection) return
    const controller = new AbortController()
    const path = scanPath(connection.organizationId, connection.scanId)
    void followEvents(path, connection.token, event => {
      setEvents(current => current.some(item => item.sequence === event.sequence)
        ? current : [...current, event].slice(-100))
      void api<Scan>(path, connection.token).then(setScan).catch(() => undefined)
      if (event.kind === 'report' || event.kind === 'status') {
        void api<Finding[]>(`${path}/findings`, connection.token).then(setFindings).catch(() => undefined)
      }
      if (event.kind === 'report') {
        void api<Report>(`${path}/report`, connection.token).then(setReport).catch(() => undefined)
      }
    }, controller.signal)
    return () => controller.abort()
  }, [connection])

  async function openScan(id: string) {
    const next = { organizationId: organizationId.trim(), scanId: id.trim(), token: token.trim() }
    const path = scanPath(next.organizationId, next.scanId)
    const current = await api<Scan>(path, next.token)
    const currentFindings = await api<Finding[]>(`${path}/findings`, next.token)
    const currentReport = current.state === 'completed'
      ? await api<Report>(`${path}/report`, next.token)
      : null
    setScan(current)
    setProjectId(current.project_id)
    setFindings(currentFindings)
    setReport(currentReport)
    setEvents([])
    setConnection(next)
    setShowCreate(false)
    setView('assessments')
  }

  async function refreshScans() {
    setError('')
    try {
      setRecentScans(await api<ScanSummary[]>(
        `/v1/organizations/${encodeURIComponent(organizationId.trim())}/projects/${encodeURIComponent(projectId.trim())}/scans`,
        token.trim(),
      ))
      await refreshOrganizationData(organizationId.trim(), token.trim())
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not list scans') }
  }

  async function refreshOrganizationData(org: string, bearer: string) {
    const prefix = `/v1/organizations/${encodeURIComponent(org)}`
    const [summary, scans, allFindings] = await Promise.all([
      api<WorkspaceSummary>(`${prefix}/workspace-summary`, bearer),
      api<OrganizationScan[]>(`${prefix}/scans`, bearer),
      api<OrganizationFinding[]>(`${prefix}/findings`, bearer),
    ])
    setWorkspaceSummary(summary)
    setOrganizationScans(scans)
    setOrganizationFindings(allFindings)
  }

  async function refreshProjects(preferredProjectId?: string, credentials?: { organizationId: string; token: string }) {
    setError('')
    try {
      const org = credentials?.organizationId ?? organizationId.trim()
      const bearer = credentials?.token ?? token.trim()
      const loaded = await api<Project[]>(`/v1/organizations/${encodeURIComponent(org)}/projects`, bearer)
      const access = await api<{ role: string; user_id: string }>(`/v1/organizations/${encodeURIComponent(org)}/access`, bearer)
      const authority = await api<AssessmentAuthorization>(`/v1/organizations/${encodeURIComponent(org)}/assessment-authorization`, bearer)
      const credits = await api<CreditBalance>(`/v1/organizations/${encodeURIComponent(org)}/credits`, bearer)
      const models = await api<ModelOption[]>(`/v1/organizations/${encodeURIComponent(org)}/models`, bearer)
      await refreshOrganizationData(org, bearer)
      setOrganizationId(org)
      setToken(bearer)
      setAccessRole(access.role)
      setAccessUserId(access.user_id)
      setAssessmentAuthorization(authority)
      setCreditBalance(credits)
      setModelOptions(models)
      setModelId(current => models.some(option => option.id === current) ? current : models[0]?.id || '')
      if (authority.scope_statement) setAuthorizationScope(authority.scope_statement)
      if (authority.active) {
        setAuthorizationSource(authority.source_allowed === true)
        setAuthorizationUrl(authority.url_allowed === true)
      }
      setProjects(loaded)
      const chosenProject = preferredProjectId || (loaded.some(item => item.id === projectId) ? projectId : loaded[0]?.id || '')
      if (chosenProject) {
        setProjectId(chosenProject)
        setRecentScans(await api<ScanSummary[]>(
          `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(chosenProject)}/scans`,
          bearer,
        ))
      } else {
        setProjectId('')
        setRecentScans([])
      }
      setAccessOpen(false)
      setView('overview')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not list projects') }
  }

  async function refreshMembers() {
    setError('')
    try {
      const prefix = `/v1/organizations/${encodeURIComponent(organizationId.trim())}`
      const [loadedMembers, loadedAudit] = await Promise.all([
        api<Member[]>(`${prefix}/members`, token.trim()),
        api<AuditEntry[]>(`${prefix}/audit-events`, token.trim()),
      ])
      setMembers(loadedMembers)
      setAuditEntries(loadedAudit)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not list members') }
  }

  async function saveAssessmentAuthorization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const path = `/v1/organizations/${encodeURIComponent(organizationId.trim())}/assessment-authorization`
      await api(path, token.trim(), { method: 'PUT', body: JSON.stringify({
        scope_statement: authorizationScope.trim(), source_allowed: authorizationSource,
        url_allowed: authorizationUrl, valid_days: authorizationDays,
        accept_terms: authorizationTermsAccepted,
      }) })
      setAssessmentAuthorization(await api<AssessmentAuthorization>(path, token.trim()))
      setAuthorizationTermsAccepted(false)
      await refreshMembers()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not save assessment authorization') }
    finally { setBusy(false) }
  }

  async function revokeAssessmentAuthorization() {
    if (!assessmentAuthorization.id) return
    setBusy(true)
    setError('')
    try {
      const prefix = `/v1/organizations/${encodeURIComponent(organizationId.trim())}/assessment-authorization`
      await api(`${prefix}/${encodeURIComponent(assessmentAuthorization.id)}`, token.trim(), { method: 'DELETE' })
      setAssessmentAuthorization({ active: false })
      await refreshMembers()
      await refreshOrganizationData(organizationId.trim(), token.trim())
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not revoke assessment authorization') }
    finally { setBusy(false) }
  }

  async function changeMemberRole(memberId: string, role: string) {
    setBusy(true)
    setError('')
    try {
      await api(`/v1/organizations/${encodeURIComponent(organizationId.trim())}/members/${encodeURIComponent(memberId)}`, token.trim(), {
        method: 'PATCH', body: JSON.stringify({ role }),
      })
      await refreshMembers()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not change member role') }
    finally { setBusy(false) }
  }

  async function removeMember(memberId: string) {
    setBusy(true)
    setError('')
    try {
      await api(`/v1/organizations/${encodeURIComponent(organizationId.trim())}/members/${encodeURIComponent(memberId)}`, token.trim(), {
        method: 'DELETE',
      })
      setRemoveMemberId('')
      await refreshMembers()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not remove member') }
    finally { setBusy(false) }
  }

  async function createProject() {
    if (!projectName.trim()) return
    setBusy(true)
    setError('')
    try {
      const path = `/v1/organizations/${encodeURIComponent(organizationId.trim())}/projects`
      const signature = `${organizationId.trim()}\n${projectName.trim()}`
      if (projectRequest.current?.signature !== signature) {
        projectRequest.current = { signature, key: crypto.randomUUID() }
      }
      const created = await api<Project>(path, token.trim(), {
        method: 'POST', body: JSON.stringify({ name: projectName.trim() }),
        headers: { 'Idempotency-Key': projectRequest.current.key },
      })
      projectRequest.current = null
      setProjectId(created.id)
      setProjectName('')
      await refreshProjects(created.id)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Project creation failed') }
    finally { setBusy(false) }
  }

  async function startScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if ((!sourceFile && !targetUrl.trim()) || !webTargetReady) return
    setBusy(true)
    setError('')
    try {
      if (sourceFile && (!sourceFile.name.toLowerCase().endsWith('.zip') || sourceFile.size < 1 || sourceFile.size > 50 * 1024 * 1024)) {
        throw new Error('Select a ZIP archive no larger than 50 MB')
      }
      const org = encodeURIComponent(organizationId.trim())
      const project = encodeURIComponent(projectId.trim())
      const bearer = token.trim()
      let artifactId: string | undefined
      if (sourceFile) {
        const upload = await api<{ id: string }>(`/v1/organizations/${org}/projects/${project}/uploads`, bearer, {
          method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() },
          body: JSON.stringify({ content_type: 'application/zip', declared_bytes: sourceFile.size }),
        })
        await uploadZip(`/v1/organizations/${org}/uploads/${encodeURIComponent(upload.id)}`, bearer, sourceFile)
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', await sourceFile.arrayBuffer())))
          .map(byte => byte.toString(16).padStart(2, '0')).join('')
        const artifact = await api<{ id: string }>(`/v1/organizations/${org}/uploads/${encodeURIComponent(upload.id)}/finalize`, bearer, {
          method: 'POST', body: JSON.stringify({ sha256: digest }),
        })
        artifactId = artifact.id
      }
      const created = await api<{ id: string }>(`/v1/organizations/${org}/projects/${project}/scans`, bearer, {
        method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() },
        body: JSON.stringify({ source_artifact_id: artifactId, target_url: targetUrl.trim() || null,
          web_target_proof_id: targetUrl.trim() ? webProof?.id : null,
          scope_note: scopeNote.trim(), profile: assessmentProfile, model_id: modelId,
          authorized: sourceMode === 'local_static' ? authorized : false }),
      })
      await openScan(created.id)
      await refreshScans()
      setCreditBalance(await api<CreditBalance>(`/v1/organizations/${org}/credits`, bearer))
      setSourceFile(null)
      setTargetUrl('')
      setWebProof(null)
      setAuthorized(false)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Scan creation failed') }
    finally { setBusy(false) }
  }

  async function startWebProof() {
    if (!targetUrl.trim() || !projectId) return
    setBusy(true)
    setError('')
    try {
      const org = organizationId.trim()
      const proof = await api<{ id: string; token: string; verification_url: string }>(
        `/v1/organizations/${encodeURIComponent(org)}/projects/${encodeURIComponent(projectId)}/web-target-proofs`,
        token.trim(), { method: 'POST', body: JSON.stringify({ target_url: targetUrl.trim() }) })
      setWebProof({ ...proof, targetUrl: targetUrl.trim(), projectId, organizationId: org, verified: false })
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not create site verification') }
    finally { setBusy(false) }
  }

  async function verifyWebProof() {
    if (!webProof || webProof.targetUrl !== targetUrl.trim() || webProof.projectId !== projectId || webProof.organizationId !== organizationId.trim()) return
    setBusy(true)
    setError('')
    try {
      await api(`/v1/organizations/${encodeURIComponent(organizationId.trim())}/projects/${encodeURIComponent(projectId)}/web-target-proofs/${encodeURIComponent(webProof.id)}/verify`,
        token.trim(), { method: 'POST' })
      setWebProof({ ...webProof, verified: true })
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Site verification failed') }
    finally { setBusy(false) }
  }

  async function selectProject(id: string) {
    setProjectId(id)
    setConnection(null)
    setScan(null)
    setFindings([])
    setReport(null)
    setEvents([])
    setRecentScans([])
    setError('')
    try {
      setRecentScans(await api<ScanSummary[]>(
        `/v1/organizations/${encodeURIComponent(organizationId.trim())}/projects/${encodeURIComponent(id)}/scans`,
        token.trim(),
      ))
      setScanProjectFilter(id)
      setView('assessments')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not list assessments') }
  }

  async function cancelScan() {
    if (!connection) return
    setBusy(true)
    setError('')
    try {
      const path = scanPath(connection.organizationId, connection.scanId)
      if (cancelRequest.current?.scanId !== connection.scanId) {
        cancelRequest.current = { scanId: connection.scanId, key: crypto.randomUUID() }
      }
      await api<{ state: string }>(`${path}/cancel`, connection.token, {
        method: 'POST', headers: { 'Idempotency-Key': cancelRequest.current.key },
      })
      cancelRequest.current = null
      setScan(await api<Scan>(path, connection.token))
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Cancellation failed') }
    finally { setBusy(false) }
  }

  async function retryScan() {
    if (!connection) return
    setBusy(true)
    setError('')
    try {
      const created = await api<{ id: string }>(
        `${scanPath(connection.organizationId, connection.scanId)}/retry`, connection.token,
        { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } },
      )
      await openScan(created.id)
      await refreshScans()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Retry failed') }
    finally { setBusy(false) }
  }

  async function ask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!connection || !question.trim()) return
    setBusy(true)
    setError('')
    try {
      const result = await api<{ answer: string }>(
        `${scanPath(connection.organizationId, connection.scanId)}/questions`, connection.token,
        { method: 'POST', body: JSON.stringify({ question: question.trim() }) },
      )
      setAnswer(result.answer)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Question failed') }
    finally { setBusy(false) }
  }

  async function downloadReport(format: 'md' | 'pdf' | 'docx') {
    if (!connection) return
    setError('')
    try {
      const path = `${scanPath(connection.organizationId, connection.scanId)}/report.${format}`
      const response = await fetch(path, { headers: { Authorization: `Bearer ${connection.token}` } })
      if (!response.ok) throw new Error(`Report download failed (${response.status})`)
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = `pentrai-${connection.scanId}.${format}`
      link.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Report download failed') }
  }

  const visibleFindings = findings.filter(item =>
    (findingSource === 'all' || item.source === findingSource) &&
    `${item.advisory_id} ${item.dependency} ${item.source_manifest}`.toLowerCase().includes(findingQuery.toLowerCase()),
  )
  const visibleOrganizationScans = organizationScans.filter(item =>
    (scanProjectFilter === 'all' || item.project_id === scanProjectFilter) &&
    `${item.id} ${item.state} ${item.project_name}`.toLowerCase().includes(scanQuery.toLowerCase()),
  )
  const visibleOrganizationFindings = organizationFindings.filter(item =>
    (findingSource === 'all' || item.source === findingSource) &&
    `${item.advisory_id} ${item.dependency} ${item.project_name} ${item.source_manifest}`.toLowerCase().includes(findingQuery.toLowerCase()),
  )
  const isConnected = Boolean(accessRole)
  const canAssess = accessRole === 'owner' || accessRole === 'security_engineer'
  const statusLabel = scan ? ({ authorized: 'Preparing', queued: 'Queued', running: 'Analyzing', cleanup: 'Finishing', completed: 'Completed', failed: 'Failed', cancelled: 'Cancelled' } as Record<string, string>)[scan.state] || scan.state : ''
  const viewLabel = { overview: 'Overview', projects: 'Projects', assessments: 'Assessments', findings: 'Findings', administration: 'Administration' }[view]
  const viewDescription = { overview: 'Your security work across every project.', projects: 'Select a project or create a new one.', assessments: 'Track assessments and open their results.', findings: 'Review detected issues across your projects.', administration: 'Manage access to this organization.' }[view]

  if (!isConnected) return <div className="sign-in-shell"><div className="sign-in-brand"><span className="brand-mark">P<span>.</span></span><strong>PentrAI</strong></div><main className="sign-in-card"><p className="eyebrow">SECURITY WORKSPACE</p><h1>{sessionChecking ? 'Opening your workspace' : 'Connect to your workspace'}</h1><p>{sessionChecking ? 'Checking your access...' : 'Enter your organization credentials to see projects, assessments, findings, and reports.'}</p>{!sessionChecking && <form onSubmit={e => { e.preventDefault(); void refreshProjects() }}><label>Organization ID<input value={organizationId} onChange={e => setOrganizationId(e.target.value)} autoComplete="off" required /></label><label>Access token<input type="password" value={token} onChange={e => setToken(e.target.value)} autoComplete="off" required /></label><button className="primary-button" disabled={busy || !organizationId.trim() || !token.trim()} type="submit">Connect workspace</button></form>}{error && <div className="error" role="alert">{error}</div>}</main></div>

  return <div className="app-shell" id="overview" data-fd-id="assessment-shell">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    <aside className="sidebar" data-fd-id="sidebar">
      <button className="brand" type="button" onClick={() => setView('overview')}><span className="brand-mark">P<span>.</span></span><span><strong>PentrAI</strong><small>Security assessments</small></span></button>
      <p className="nav-caption">WORKSPACE / {projects.length} PROJECTS</p>
      <nav aria-label="Main navigation">
        <button className={view === 'overview' ? 'nav-active' : ''} aria-current={view === 'overview' ? 'page' : undefined} type="button" onClick={() => setView('overview')}><span className="nav-index">01</span>Overview</button>
        <button className={view === 'projects' ? 'nav-active' : ''} aria-current={view === 'projects' ? 'page' : undefined} type="button" onClick={() => setView('projects')}><span className="nav-index">02</span>Projects</button>
        <button className={view === 'assessments' ? 'nav-active' : ''} aria-current={view === 'assessments' ? 'page' : undefined} type="button" onClick={() => setView('assessments')}><span className="nav-index">03</span>Assessments</button>
        <button className={view === 'findings' ? 'nav-active' : ''} aria-current={view === 'findings' ? 'page' : undefined} type="button" onClick={() => setView('findings')}><span className="nav-index">04</span>Findings</button>
        {accessRole === 'owner' && <button className={view === 'administration' ? 'nav-active' : ''} aria-current={view === 'administration' ? 'page' : undefined} type="button" onClick={() => { setView('administration'); void refreshMembers() }}><span className="nav-index">05</span>Administration</button>}
      </nav>
      <div className="sidebar-foot"><span className="sidebar-foot-mark" aria-hidden="true">↗</span><strong>Assessment workspace</strong><small>Authorized security review</small></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><span className="topbar-path">PentrAI <b>/</b> Workspace <b>/</b> <strong>{viewLabel}</strong></span><button className="access-trigger" type="button" aria-expanded={accessOpen} onClick={() => setAccessOpen(value => !value)}><i className="connected" />{accessRole === 'owner' ? 'Owner' : accessRole === 'security_engineer' ? 'Security engineer' : 'Developer'} workspace <span aria-hidden="true">⌄</span></button></header>
      <main className="main" id="main-content">
        <section className="page-heading"><div><p className="eyebrow">SECURITY / {viewLabel.toUpperCase()}</p><h1>{view === 'overview' ? 'Your security workspace' : viewLabel}</h1><p>{viewDescription}</p></div>{view !== 'administration' && canAssess && <button className="primary-button" type="button" onClick={() => { if (!projects.length) { setView('projects'); return } setView('assessments'); setShowCreate(true) }}><span className="button-plus" aria-hidden="true">+</span> New assessment</button>}</section>

        {accessOpen && <section className="access-card"><div><span className="section-icon">◇</span><h2>Switch workspace</h2><p>Use another organization's access details to switch workspaces.</p></div><form className="access-fields" onSubmit={e => { e.preventDefault(); void refreshProjects() }}><label>Organization ID<input value={organizationId} onChange={e => { disconnectWorkspace(); setOrganizationId(e.target.value) }} autoComplete="off" placeholder="Organization ID" /></label><label>Access token<input type="password" value={token} onChange={e => { disconnectWorkspace(); setToken(e.target.value) }} autoComplete="off" placeholder="Access token" /></label><button className="primary-button" disabled={busy || !organizationId.trim() || !token.trim()} type="submit">Connect <span aria-hidden="true">→</span></button></form></section>}
        {error && <div className="error" role="alert"><strong>Action needed</strong><span>{error}</span><button type="button" onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}

        {view === 'overview' && workspaceSummary && <section className="overview-grid" aria-label="Workspace overview">
          <div className="overview-lead"><span className="overview-kicker">ASSESSMENT LEDGER <span aria-hidden="true">↗</span></span><div><strong>{workspaceSummary.assessments}</strong><h2>Assessments across your projects</h2><p>Open a completed review, inspect a finding, or start a new authorized assessment.</p></div><button type="button" onClick={() => setView('assessments')}>View assessments <span aria-hidden="true">↗</span></button></div>
          <div className="overview-metrics"><button className="overview-card" type="button" onClick={() => setView('projects')}><span className="eyebrow">PROJECTS IN SCOPE</span><strong>{workspaceSummary.projects}</strong><span>Open projects <span aria-hidden="true">↗</span></span></button><button className="overview-card" type="button" onClick={() => setView('findings')}><span className="eyebrow">FINDINGS TO REVIEW</span><strong>{workspaceSummary.findings}</strong><span>Review findings <span aria-hidden="true">↗</span></span></button><button className="overview-card overview-card-wide" type="button" onClick={() => { setView('assessments'); setScanQuery('completed') }}><span className="eyebrow">COMPLETED REVIEWS</span><strong>{workspaceSummary.completed}</strong><span>Open reports <span aria-hidden="true">↗</span></span></button></div>
        </section>}

        {view === 'overview' && isConnected && projects.length === 0 && <section className="projects-card empty-workspace"><h2>{canAssess ? 'Create your first project' : 'No projects available'}</h2><p>{canAssess ? 'Projects keep assessments and reports together.' : 'Ask an organization owner to grant access to a project.'}</p>{canAssess && <button className="primary-button" type="button" onClick={() => setView('projects')}>Create a project</button>}</section>}

        {view === 'projects' && <section className="projects-card" aria-label="Projects"><div className="section-title-row"><div><p className="eyebrow">SOURCE ORGANIZATION</p><h2>Your projects</h2></div><button className="outline-button" type="button" disabled={!organizationId.trim() || !token.trim()} onClick={() => void refreshProjects()}>Refresh</button></div>{projects.length ? <div className="project-list">{projects.map(item => <button key={item.id} type="button" className={item.id === projectId ? 'selected' : ''} onClick={() => void selectProject(item.id)}><strong>{item.name}</strong><span>{item.id === projectId ? 'Current project' : 'Open project'} →</span></button>)}</div> : <p className="empty">{isConnected ? 'No projects in this workspace.' : 'Connect your workspace to see projects.'}</p>}{canAssess && <div className="project-create"><label>New project name<input value={projectName} onChange={e => setProjectName(e.target.value)} maxLength={200} placeholder="Name your project" /></label><button className="primary-button" disabled={busy || !projectName.trim() || !organizationId.trim() || !token.trim()} type="button" onClick={() => void createProject()}>Create project</button></div>}</section>}

        {view === 'administration' && accessRole === 'owner' && <section className="members-card authorization-card" aria-label="Assessment authorization">
          <div className="section-title-row"><div><p className="eyebrow">ASSESSMENT AUTHORITY</p><h2>Organization authorization</h2><p>Record the scope your organization may assess. Security engineers can start scans within this approval.</p></div></div>
          {assessmentAuthorization.active && <div className="authorization-active"><span className="status-pill status-completed"><i />Active authorization</span><strong>Approved through {new Date(assessmentAuthorization.expires_at || '').toLocaleDateString()}</strong><p>{assessmentAuthorization.scope_statement}</p></div>}
          {creditBalance && <div className="credit-summary" aria-label="Assessment credits"><div><span>AVAILABLE CREDITS</span><strong>{creditBalance.available.toLocaleString()}</strong></div><div><span>RESERVED</span><strong>{creditBalance.reserved.toLocaleString()}</strong></div><div><span>USED</span><strong>{creditBalance.spent.toLocaleString()}</strong></div></div>}
          <form className="authorization-form" onSubmit={saveAssessmentAuthorization}>
            <div className="authorization-fields"><label>Authorized scope<textarea value={authorizationScope} minLength={20} maxLength={2000} required onChange={e => setAuthorizationScope(e.target.value)} placeholder="Describe the applications and websites your organization may assess" /></label><p>Include the applications, domains, and limits covered by your permission.</p></div>
            <div className="authorization-options"><div><p className="eyebrow">PERMITTED ASSESSMENTS</p><label className="attestation"><input type="checkbox" checked={authorizationSource} onChange={e => setAuthorizationSource(e.target.checked)} /><span>Source code</span></label><label className="attestation"><input type="checkbox" checked={authorizationUrl} onChange={e => setAuthorizationUrl(e.target.checked)} /><span>Verified websites</span></label></div><label>Approval duration <span className="field-hint">days, up to 365</span><input type="number" min={1} max={365} value={authorizationDays} onChange={e => setAuthorizationDays(Number(e.target.value))} /></label></div>
            <div className="authorization-footer"><label className="attestation"><input type="checkbox" checked={authorizationTermsAccepted} onChange={e => setAuthorizationTermsAccepted(e.target.checked)} required /><span>I can bind this organization, and it owns or has written permission to assess the targets within this scope. Website control must be verified; disruptive tests require separate approval.</span></label><button className="primary-button" type="submit" disabled={busy || !authorizationTermsAccepted || authorizationScope.trim().length < 20 || (!authorizationSource && !authorizationUrl)}>Save authorization</button></div>
          </form>
          {assessmentAuthorization.active && <button className="text-button danger" type="button" disabled={busy} onClick={() => void revokeAssessmentAuthorization()}>Revoke authorization and cancel pending assessments</button>}
        </section>}

        {view === 'administration' && accessRole === 'owner' && <section className="members-card" aria-label="Organization members"><div className="section-title-row"><div><p className="eyebrow">ACCESS CONTROL</p><h2>Members</h2><p>Role changes take effect on the next request. New identities are provisioned through your identity provider.</p></div><button className="outline-button" type="button" onClick={() => void refreshMembers()}>Refresh</button></div><div className="member-list">{members.map(member => <div className="member-row" key={member.id}><div><strong>{member.identity}</strong>{member.user_id === accessUserId && <small> You</small>}</div><label>Role<select aria-label={`Role for ${member.identity}`} disabled={busy || member.user_id === accessUserId} value={member.role} onChange={e => void changeMemberRole(member.id, e.target.value)}><option value="owner">Owner</option><option value="security_engineer">Security engineer</option><option value="developer">Developer</option></select></label>{removeMemberId === member.id ? <div className="member-confirm"><span>Remove this member?</span><button className="text-button danger" disabled={busy} type="button" onClick={() => void removeMember(member.id)}>Confirm</button><button className="text-button" type="button" onClick={() => setRemoveMemberId('')}>Cancel</button></div> : <button className="text-button danger" disabled={busy || member.user_id === accessUserId} type="button" onClick={() => setRemoveMemberId(member.id)}>Remove</button>}</div>)}</div></section>}

        {view === 'administration' && accessRole === 'owner' && <section className="audit-card" aria-label="Recent organization activity"><div className="section-title-row"><div><p className="eyebrow">AUDIT TRAIL</p><h2>Recent activity</h2></div></div><div className="audit-list">{auditEntries.length ? auditEntries.map(entry => <div key={entry.id}><strong>{({ 'member.role_change': 'Member role changed', 'member.remove': 'Member removed', 'project.create': 'Project created' } as Record<string, string>)[entry.action] || entry.action.replaceAll('.', ' ')}</strong><time>{new Date(entry.created_at).toLocaleString()}</time></div>) : <p className="empty">No recent activity.</p>}</div></section>}

        {view === 'assessments' && scan && <section className="summary-card" id="assessment"><div className="summary-top"><div><p className="eyebrow">CURRENT ASSESSMENT</p><h2>{scan.target_url ? 'Website assessment' : 'Source review'} <span>#{scan.id.slice(0, 8)}</span></h2><p>{projects.find(item => item.id === scan.project_id)?.name || 'Project assessment'}</p></div><span className={`status-pill status-${scan.state}`}><i />{statusLabel}</span></div><div className="summary-stats"><div><small>DETECTED ISSUES</small><strong>{findings.length}</strong><span>Require review and validation</span></div><div><small>ANALYSIS</small><strong>{scan.target_url ? 'Website and source scope' : 'Static source review'}</strong><span>See report for coverage and limitations</span></div><div><small>REPORT</small><strong>{report ? 'Ready' : 'Pending'}</strong><span>{report ? 'Available in three formats' : 'Available when analysis finishes'}</span></div></div><div className="summary-bottom"><p><strong>Declared scope:</strong> {scan.scope_note || 'Recorded with this assessment'}</p>{scan.target_url && <p><strong>Website:</strong> {scan.target_url}</p>}{scan.reserved_credits > 0 && <p><strong>AI model:</strong> {modelOptions.find(option => option.id === scan.model_id)?.label || scan.model_id} · {scan.charged_credits.toLocaleString()} credits used from {scan.reserved_credits.toLocaleString()} reserved</p>}{(scan.state === 'authorized' || scan.state === 'queued') && <button className="text-button danger" disabled={busy} type="button" onClick={() => void cancelScan()}>Cancel assessment</button>}{(scan.state === 'failed' || scan.state === 'cancelled') && <button className="text-button" disabled={busy} type="button" onClick={() => void retryScan()}>Retry assessment →</button>}</div></section>}

        {view === 'assessments' && showCreate && <section className="create-layout" id="new-assessment">
          <form className="form-card" onSubmit={startScan}>
            <div className="section-heading"><div><p className="eyebrow">NEW ASSESSMENT</p><h2 data-fd-id="form-title">Submit an application</h2><p data-fd-id="form-description">{!sourceScansAvailable ? 'Assessment execution is temporarily unavailable.' : webScansAvailable ? 'Add source code, a verified website, or both, then confirm your authority to assess them.' : 'Add a source ZIP archive and confirm your authority to assess it.'}</p></div><button className="text-button" type="button" onClick={() => setShowCreate(false)}>Close</button></div>
            <div className="form-body">
              <h3><span>01</span> Project</h3>
              <div className="project-row"><label>Project<select data-fd-id="field-project" value={projectId} onChange={e => setProjectId(e.target.value)} required><option value="">Select a project</option>{projects.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><button className="outline-button" type="button" onClick={() => setView('projects')}>Manage projects</button></div>
              <h3><span>02</span> Application source or website</h3>
              <label className={`upload-zone ${sourceFile ? 'has-file' : ''}`}><input type="file" accept=".zip,application/zip" onChange={e => setSourceFile(e.target.files?.[0] ?? null)} /><span className="upload-symbol">ZIP</span><strong>{sourceFile ? sourceFile.name : `Choose a ZIP archive${webScansAvailable ? ' (optional)' : ''}`}</strong><small>{sourceFile ? `${(sourceFile.size / 1024).toFixed(1)} KB - Ready to upload` : 'ZIP format - Up to 50 MB'}</small></label>
              {webScansAvailable && <label>Website URL (optional)<input type="url" value={targetUrl} maxLength={2048} onChange={e => { setTargetUrl(e.target.value); setWebProof(null) }} placeholder="https://your-app.example.com" /></label>}
              {webScansAvailable && targetUrl.trim() && <div className="web-proof"><button className="outline-button" type="button" disabled={busy || !projectId} onClick={() => void startWebProof()}>Get verification code</button>{webProof && <div><p>Place this exact code at <strong>{webProof.verification_url}</strong></p><code>{webProof.token}</code><p>Make the file publicly readable, then verify this site.</p><button className="outline-button" type="button" disabled={busy || webProof.verified} onClick={() => void verifyWebProof()}>{webProof.verified ? 'Site verified' : 'Verify site'}</button></div>}</div>}
              <h3><span>03</span> Assessment depth</h3>
              {sourceMode !== 'local_static' && <label>AI model<select value={modelId} onChange={e => setModelId(e.target.value)} required>{modelOptions.map(option => <option key={option.id} value={option.id}>{option.label} · {option.prompt_credit_rate} input / {option.completion_credit_rate} output credits per token</option>)}</select></label>}
              <div className="profile-options" role="radiogroup" aria-label="Assessment depth">
                {([
                  ['quick', 'Quick', sourceMode === 'local_static' ? 'Dependency checks' : 'Focused HexStrike review'],
                  ['standard', 'Standard', sourceMode === 'local_static' ? 'Dependencies and selected code checks' : 'Broader HexStrike review'],
                  ['deep', 'Deep', sourceMode === 'local_static' ? 'Selected code checks with a higher finding limit' : 'Highest HexStrike work budget'],
                ] as const).map(([value, title, description]) => <label key={value} className={assessmentProfile === value ? 'profile-selected' : ''}><input type="radio" name="assessment-depth" value={value} checked={assessmentProfile === value} onChange={() => setAssessmentProfile(value)} /><strong>{title}</strong><small>{description}</small></label>)}
              </div>
              <h3><span>04</span> Assessment scope</h3>
              <label>What should this assessment cover?<input data-fd-id="field-scope" required value={scopeNote} maxLength={2000} onChange={e => setScopeNote(e.target.value)} placeholder="For example, the application source and its public website" /></label>
              <p className="coverage-note"><strong>Current coverage:</strong> {sourceMode === 'local_static' ? 'Exact Python package pins and selected Python source patterns.' : 'Model-selected HexStrike tools within the approved scope and work budget.'} Review the report for coverage and limitations.</p>
              {sourceMode === 'local_static' ? <label className="attestation"><input required type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} /><span>I own or have permission to assess the submitted application and website.</span></label> : !assessmentAuthorization.active ? <p className="coverage-note">An organization owner must approve assessment scope in Administration before scans can start.</p> : null}
              <button className="primary-button submit-button" disabled={busy || !sourceScansAvailable || (sourceMode === 'local_static' ? !authorized : !modelId || !assessmentAuthorization.active || (sourceFile !== null && !assessmentAuthorization.source_allowed) || (!!targetUrl.trim() && !assessmentAuthorization.url_allowed)) || (!sourceFile && !targetUrl.trim()) || !webTargetReady || !organizationId.trim() || !projectId.trim() || !token.trim()} type="submit">{busy ? 'Starting assessment...' : 'Start assessment'}</button>
            </div>
          </form>
        </section>}

        {(view === 'overview' || view === 'assessments') && <section className="recent-section" aria-label="Assessment history">
          <div className="section-title-row"><div><p className="eyebrow">ACROSS YOUR PROJECTS</p><h2>{view === 'overview' ? 'Latest assessments' : 'All assessments'}</h2></div><button className="text-button" type="button" onClick={() => void refreshOrganizationData(organizationId, token)}>Refresh →</button></div>
          {view === 'assessments' && <div className="assessment-filters"><input aria-label="Search assessments" value={scanQuery} onChange={e => setScanQuery(e.target.value)} placeholder="Search ID, project, or status" /><select aria-label="Filter assessments by project" value={scanProjectFilter} onChange={e => setScanProjectFilter(e.target.value)}><option value="all">All projects</option>{projects.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></div>}
          <div className="recent-list">{(view === 'overview' ? organizationScans.slice(0, 5) : visibleOrganizationScans).length ? (view === 'overview' ? organizationScans.slice(0, 5) : visibleOrganizationScans).map(item => <button key={item.id} type="button" onClick={() => void openScan(item.id).catch(cause => setError(String(cause)))}><span className="recent-icon">▤</span><span><strong>{item.project_name}</strong><small>Assessment #{item.id.slice(0, 8)} · {new Date(item.created_at).toLocaleDateString()}</small></span><em>{item.state}</em><span>→</span></button>) : <div className="empty-activity"><h3>{organizationScans.length ? 'No assessments match your filters' : 'No assessments yet'}</h3><p>{organizationScans.length ? 'Try a different project or search.' : 'Submit a ZIP archive to get findings and a report.'}</p>{canAssess && !organizationScans.length && <button className="primary-button" type="button" onClick={() => { setView('assessments'); setShowCreate(true) }}>Start an assessment</button>}</div>}</div>
        </section>}

        {view === 'overview' && organizationFindings.length > 0 && <section className="organization-findings"><div className="section-title-row"><div><p className="eyebrow">REQUIRES REVIEW</p><h2>Recent findings</h2></div><button className="text-button" type="button" onClick={() => setView('findings')}>View all →</button></div><div className="organization-finding-list">{organizationFindings.slice(0, 5).map(item => <button key={item.id} type="button" onClick={() => void openScan(item.scan_id).catch(cause => setError(String(cause)))}><span><strong>{item.title || item.advisory_id}</strong><small>{item.project_name} · {item.dependency || 'Python source'}</small></span><span className="detected-pill">{item.state}</span><span>View assessment →</span></button>)}</div></section>}

        {view === 'overview' && <section className="overview-projects"><div className="section-title-row"><div><p className="eyebrow">SOURCE ORGANIZATION</p><h2>Projects</h2></div><button className="text-button" type="button" onClick={() => setView('projects')}>View all →</button></div><div className="project-shortcuts">{projects.slice(0, 4).map(item => <button key={item.id} type="button" onClick={() => void selectProject(item.id)}><strong>{item.name}</strong><span>{organizationScans.filter(scanItem => scanItem.project_id === item.id).length} recent assessments →</span></button>)}</div></section>}

        {view === 'findings' && <section className="organization-findings"><div className="section-title-row"><div><p className="eyebrow">DETECTED ISSUES</p><h2>Findings across projects</h2><p>Scanner detections need review and validation.</p></div><button className="text-button" type="button" onClick={() => void refreshOrganizationData(organizationId, token)}>Refresh →</button></div><div className="assessment-filters"><input aria-label="Search all findings" value={findingQuery} onChange={e => setFindingQuery(e.target.value)} placeholder="Search advisory, component, or project" /><select aria-label="Filter all findings by source" value={findingSource} onChange={e => setFindingSource(e.target.value)}><option value="all">All sources</option><option value="sca">Dependencies</option><option value="sast">Code checks</option><option value="hexstrike">HexStrike</option></select></div><div className="organization-finding-list">{visibleOrganizationFindings.length ? visibleOrganizationFindings.map(item => <button key={item.id} type="button" onClick={() => void openScan(item.scan_id).catch(cause => setError(String(cause)))}><span><strong>{item.title || item.advisory_id}</strong><small>{item.project_name} · {item.dependency || 'Python source'} · {item.source_manifest}</small></span><span className="detected-pill">{item.state}</span><span>View assessment →</span></button>) : <div className="empty-activity"><h3>{organizationFindings.length ? 'No findings match your filters' : 'No findings to review'}</h3><p>{organizationFindings.length ? 'Try a different search or source.' : 'Findings appear after a supported assessment completes. An empty list does not establish that source is secure.'}</p></div>}</div></section>}

        {view === 'assessments' && scan && <><section className="results-section" id="findings"><div className="section-title-row"><div><p className="eyebrow">ANALYSIS RESULTS</p><h2>Detected findings <span className="count">{findings.length}</span></h2><p>These results identify issues for review. They do not establish exploitability.</p></div></div><div className="results-card"><div className="results-toolbar"><label className="search-field"><span aria-hidden="true">⌕</span><input aria-label="Search findings" value={findingQuery} onChange={e => setFindingQuery(e.target.value)} placeholder="Search advisory or component" /></label><select aria-label="Filter findings by source" value={findingSource} onChange={e => setFindingSource(e.target.value)}><option value="all">All sources</option><option value="sca">Dependencies</option><option value="sast">Code checks</option><option value="hexstrike">HexStrike</option></select></div>{visibleFindings.length ? <div className="finding-table"><div className="table-head"><span>FINDING</span><span>COMPONENT</span><span>SOURCE</span><span>STATUS</span></div>{visibleFindings.map(item => <details className="finding-row" key={item.id}><summary><strong>{item.title || item.advisory_id}</strong><span>{item.dependency || (item.source === 'hexstrike' ? 'Application' : 'Python source')}</span><span>{item.source === 'sca' ? 'Dependency' : item.source === 'hexstrike' ? 'HexStrike' : 'Code check'}</span><span className="detected-pill">{item.state}</span></summary><div className="finding-detail">{item.explanation && <p>{item.explanation}</p>}{item.severity && <span>Severity: {item.severity}</span>}{item.source_manifest && <span>Source: {item.source_manifest}</span>}<span>Scanner: {item.scanner_version}</span><span>Database: {item.database_version}</span></div></details>)}</div> : <p className="empty">{findings.length ? 'No findings match your filters.' : 'Findings will appear when analysis is complete. Review the report for coverage and limitations.'}</p>}</div></section><div className="lower-grid"><section className="detail-card" id="activity"><div className="section-title-row"><div><p className="eyebrow">ASSESSMENT HISTORY</p><h2>Activity</h2></div><span className="heading-glyph">◷</span></div>{events.length ? <ol className="activity-list">{events.map(item => <li key={item.sequence}><span className="activity-node" /><div><strong>{priorEventLabels[item.summary] || item.summary}</strong><small>Step {String(item.sequence).padStart(2, '0')}</small></div></li>)}</ol> : <p className="empty">Updates will appear here as the assessment progresses.</p>}</section><section className="detail-card" id="report"><div className="section-title-row"><div><p className="eyebrow">DELIVERABLE</p><h2>Assessment report</h2></div><span className="heading-glyph">▤</span></div>{report ? <><p className="report-description">The report includes declared scope, detected issues, scanner provenance, and coverage limitations.</p><div className="report-actions"><button type="button" onClick={() => void downloadReport('pdf')}>↓ PDF</button><button type="button" onClick={() => void downloadReport('docx')}>↓ DOCX</button><button type="button" onClick={() => void downloadReport('md')}>↓ Markdown</button></div><button className="text-button preview-toggle" type="button" onClick={() => setShowReportText(value => !value)}>{showReportText ? 'Hide report text' : 'Read report text'} →</button>{showReportText && <pre className="report-text">{report.markdown}</pre>}</> : <p className="empty">Your report will be available when the assessment is complete.</p>}</section></div><section className="question-card"><div><p className="eyebrow">ASSESSMENT ASSISTANT</p><h2>Ask about this assessment</h2><p>Answers use the recorded status, findings, and report availability.</p></div><form className="question" onSubmit={ask}><input aria-label="Question about assessment" value={question} onChange={e => setQuestion(e.target.value)} placeholder="What is the current status?" maxLength={500} /><button className="primary-button" disabled={busy || !question.trim()}>Ask →</button></form>{answer && <p className="answer">{answer}</p>}</section></>}

      </main>
    </div>
  </div>
}
