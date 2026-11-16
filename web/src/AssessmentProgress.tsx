import type { LiveStatus, Scan } from './api'
import { ASSESSMENT_STAGES, durationLabel, progressView } from './progressModel'

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' })

export function activityTime(value?: string | null): string {
  const parsed = value ? new Date(value) : null
  return parsed && Number.isFinite(parsed.getTime()) ? dateTime.format(parsed) : 'Not yet confirmed'
}

type Props = { scan: Scan; live: LiveStatus; snapshotFailed: boolean; refreshing: boolean; onRefresh: () => void }

export default function AssessmentProgress({ scan, live, snapshotFailed, refreshing, onRefresh }: Props) {
  const view = progressView(scan, live, snapshotFailed)
  const progress = scan.progress
  return <section className={`assessment-progress progress-${view.tone}`} aria-labelledby="assessment-progress-title">
    <div className="progress-heading">
      <div>
        <p className="eyebrow">ASSESSMENT PROGRESS</p>
        <div aria-live="polite" aria-atomic="true">
          <h2 id="assessment-progress-title">{view.title}</h2>
          <p className="progress-message">{view.message}</p>
        </div>
      </div>
      <div className="progress-connection">
        <span className="progress-signal"><i aria-hidden="true" />{view.connectionLabel}</span>
        <button className="outline-button" type="button" disabled={refreshing} onClick={onRefresh}>
          {refreshing ? 'Checking status…' : 'Check status'}
        </button>
      </div>
    </div>
    <p className="progress-position">{progress
      ? view.completed ? 'All assessment stages complete' : `Stage ${view.index + 1} of ${ASSESSMENT_STAGES.length}`
      : 'Waiting for stage details'}<span>Stages reflect confirmed activity, not an estimated completion percentage.</span></p>
    <ol className="progress-stages" aria-label="Assessment stages">
      {ASSESSMENT_STAGES.map((stage, index) => {
        const done = !!progress && (view.completed || index < view.index)
        const current = !!progress && !view.terminal && index === view.index
        return <li key={stage.id} className={done ? 'stage-done' : current ? 'stage-current' : 'stage-pending'} aria-current={current ? 'step' : undefined}>
          <span className="stage-number" aria-hidden="true">{done ? '✓' : String(index + 1).padStart(2, '0')}</span>
          <div><strong>{stage.label}</strong><small>{done ? 'Complete' : current ? stage.description : view.terminal ? 'Not completed' : 'Upcoming'}</small></div>
        </li>
      })}
    </ol>
    <dl className="progress-metadata">
      <div><dt>Elapsed time</dt><dd>{progress ? durationLabel(progress.elapsed_seconds) : 'Not yet confirmed'}</dd></div>
      <div><dt>Last assessment activity</dt><dd><time dateTime={progress?.last_activity_at}>{activityTime(progress?.last_activity_at)}</time></dd></div>
      <div><dt>Last status check</dt><dd><time dateTime={progress?.checked_at}>{activityTime(progress?.checked_at)}</time></dd></div>
      <div><dt>Assessment reference</dt><dd className="assessment-reference">{scan.id}</dd></div>
    </dl>
  </section>
}
