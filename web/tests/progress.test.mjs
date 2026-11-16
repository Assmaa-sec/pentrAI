import test from 'node:test'
import assert from 'node:assert/strict'
import { progressView, durationLabel, assessmentLabel } from '../src/progressModel.ts'
import { followEvents } from '../src/api.ts'

const sample = { id: 'owned-scan', state: 'queued', progress: {
  stage: 'analysis', health: 'healthy', message: 'Reviewing the approved source', elapsed_seconds: 65,
} }
const turn = () => new Promise(resolve => setImmediate(resolve))
const frames = chunks => new Response(new ReadableStream({
  start(controller) { for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk)); controller.close() },
}), { headers: { 'Content-Type': 'text/event-stream' } })

test('actual stage and independent connection health drive presentation', () => {
  assert.equal(progressView(sample, 'connected', false).index, 2)
  assert.equal(progressView(sample, 'connected', false).title, 'Analysis in progress')
  assert.equal(progressView(sample, 'connected', true).title, 'Assessment updates unavailable')
  assert.equal(progressView(sample, 'reconnecting', false).tone, 'warning')
  assert.equal(progressView(sample, 'unavailable', true).title, 'Workspace access needs attention')
  assert.equal(progressView({ ...sample, progress: { ...sample.progress, health: 'interrupted' } }, 'connected', false).title, 'Progress needs attention')
  for (const state of ['failed', 'cancelled', 'completed']) {
    const view = progressView({ ...sample, state }, 'reconnecting', true)
    assert.equal(view.terminal, true)
    assert.notEqual(view.title, 'Live updates interrupted')
  }
  assert.equal(durationLabel(3665), '1h 1m')
  assert.equal(durationLabel(65), '1m 5s')
  assert.equal(durationLabel(NaN), 'Not available')
  assert.equal(assessmentLabel('reporting'), 'Preparing report')
})

test('SSE accepts fragmented CRLF and ignores duplicate event sequences', async t => {
  const abort = new AbortController()
  const events = []
  t.mock.method(globalThis, 'fetch', async () => frames([
    ': heartbeat\r', '\n\r\n', 'data: {"sequence":1,"kind":"analysis","summary":"First"}\r',
    '\n\r\ndata: {"sequence":1,"kind":"analysis","summary":"Duplicate"}\n\n',
    'data:{"sequence":2,"kind":"report","summary":"Second"}\n\n',
  ]))
  await followEvents('/owned', 'test', event => { events.push(event); if (event.sequence === 2) abort.abort() }, abort.signal)
  assert.deepEqual(events.map(event => event.sequence), [1, 2])
})

test('changing assessment cancels buffered events from its previous stream', async t => {
  const abort = new AbortController()
  const events = []
  t.mock.method(globalThis, 'fetch', async () => frames([
    'data: {"sequence":1}\n\ndata: {"sequence":2}\n\n',
  ]))
  await followEvents('/old', 'test', event => { events.push(event); abort.abort() }, abort.signal)
  assert.deepEqual(events.map(event => event.sequence), [1])
})

test('silent streams time out and visibly reconnect instead of waiting forever', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const abort = new AbortController()
  const states = []
  t.mock.method(globalThis, 'fetch', async (_path, options) => new Response(new ReadableStream({
    start(controller) { options.signal.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')), { once: true }) },
  })))
  const running = followEvents('/owned', 'test', () => {}, abort.signal, state => {
    states.push(state)
    if (state === 'reconnecting') abort.abort()
  })
  await turn()
  t.mock.timers.tick(45001)
  await running
  assert.ok(states.includes('connected'))
  assert.ok(states.includes('reconnecting'))
})

test('reconnections resume from last event without repeating earlier activity', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const abort = new AbortController()
  const headers = []
  const events = []
  t.mock.method(globalThis, 'fetch', async (_path, options) => {
    headers.push(options.headers)
    return frames([`data: {"sequence":${headers.length}}\n\n`])
  })
  const running = followEvents('/owned', 'test', event => { events.push(event.sequence); if (events.length === 2) abort.abort() }, abort.signal)
  await turn()
  t.mock.timers.tick(2001)
  await running
  assert.deepEqual(events, [1, 2])
  assert.equal(headers[1]['Last-Event-ID'], '1')
})

test('expired access is visible and does not loop indefinitely', async t => {
  const states = []
  let requests = 0
  t.mock.method(globalThis, 'fetch', async () => { requests++; return new Response('', { status: 401 }) })
  await followEvents('/owned', 'test', () => {}, new AbortController().signal, state => states.push(state))
  assert.equal(requests, 1)
  assert.ok(states.includes('unavailable'))
})
