import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { sendJson, useApi, usePolling } from '../api'
import type { DeploymentState, DeploymentStatus, Group, Paginated, PatchOption, Policy, StageProgress, StageState } from '../api'
import { SeverityBadge } from '../components/SeverityBadge'
import { useTooltip } from '../components/Tooltip'
import { SEVERITY_LABEL, STATUS_GLYPH, STATUS_LABEL, STATUS_ORDER, formatDateTime, formatPercent, severityKey } from '../labels'

const REFRESH_MS = 5000

export default function PolicyDetail() {
  const { id } = useParams()
  const policy = useApi<Policy>(`/api/policies/${id}/`)
  const groups = useApi<Paginated<Group>>('/api/groups/')

  return (
    <main className="page">
      <p>
        <Link to="/policies">← 정책 목록</Link>
      </p>
      {policy.loading && <div className="notice">불러오는 중…</div>}
      {policy.error && <div className="notice error">정책을 불러오지 못했습니다. {policy.error}</div>}
      {policy.data && <Detail policy={policy.data} groups={groups.data?.results ?? []} />}
    </main>
  )
}

function Detail({ policy, groups }: { policy: Policy; groups: Group[] }) {
  const groupName = new Map(groups.map((group) => [group.id, group.name]))
  const [version, setVersion] = useState(0) // 배포를 시작한 뒤 고를 수 있는 패치 목록을 다시 불러오려고 쓰는 값
  const options = useApi<{ results: PatchOption[] }>(`/api/patches/?policy=${policy.id}&r=${version}`)
  const deployments = usePolling<DeploymentStatus[]>(`/api/policies/${policy.id}/status/`, REFRESH_MS)

  const [chosen, setChosen] = useState('')
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState<string | null>(null)

  const patches = options.data?.results ?? []
  const selected = patches.some((patch) => String(patch.id) === chosen) ? chosen : String(patches[0]?.id ?? '')
  const anyRunning = deployments.data?.some((item) => item.state === 'running') ?? false

  async function start(event: FormEvent) {
    event.preventDefault()
    if (!selected) return
    setStarting(true)
    setStartError(null)
    try {
      await sendJson('POST', `/api/policies/${policy.id}/deploy/`, { patch: Number(selected) })
      setVersion((value) => value + 1)
      deployments.reload()
    } catch (error) {
      setStartError(error instanceof Error ? error.message : '배포를 시작하지 못했습니다.')
    } finally {
      setStarting(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{policy.name}</h1>
          <p className="lede">
            대상 패치: <SeverityBadge severity={policy.min_severity} /> 이상 · 실행 시각{' '}
            {policy.start_time ? policy.start_time.slice(0, 5) : '지정 안 함'} · {policy.is_active ? '사용' : '꺼 둠'}
          </p>
        </div>
        <Link className="btn" to={`/policies/${policy.id}/edit`}>
          편집
        </Link>
      </div>

      <h2 className="section-title">배포 단계</h2>
      {policy.stages.length === 0 ? (
        <div className="notice">배포 단계가 없습니다. 편집에서 단계를 넣으세요.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>단계</th>
                <th>그룹</th>
                <th className="num">이전 단계 후 대기(분)</th>
                <th className="num">롤백 오류율</th>
              </tr>
            </thead>
            <tbody>
              {[...policy.stages]
                .sort((a, b) => a.order - b.order)
                .map((stage) => (
                  <tr key={stage.order}>
                    <td>{stage.order}단계</td>
                    <td>{groupName.get(stage.group) ?? `그룹 ${stage.group}`}</td>
                    <td className="num">{stage.delay_minutes}</td>
                    <td className="num">{formatPercent(stage.rollback_error_rate)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 className="section-title">배포 시작</h2>
      <form className="card deploy-form" onSubmit={start}>
        {!policy.is_active ? (
          <p className="muted">꺼 둔 정책은 배포할 수 없습니다. 편집에서 "사용"을 켜세요.</p>
        ) : options.loading ? (
          <p className="muted">배포할 수 있는 패치를 찾는 중…</p>
        ) : patches.length === 0 ? (
          <p className="muted">
            배포할 수 있는 패치가 없습니다. 이 정책의 최소 위험도({SEVERITY_LABEL[severityKey(policy.min_severity)]}) 이상인 CVE를 해결하고
            진행 중인 배포가 없는 패치만 나옵니다.
          </p>
        ) : (
          <>
            <label className="field">
              <span>배포할 패치 (한 번에 하나)</span>
              <select value={selected} onChange={(event) => setChosen(event.target.value)}>
                {patches.map((patch) => (
                  <option key={patch.id} value={patch.id}>
                    {patch.kb_number} · {patch.target_os} · 위험도 {SEVERITY_LABEL[severityKey(patch.max_severity)]}
                    {patch.is_error_reported ? ' · 오류 보고됨' : ''}
                  </option>
                ))}
              </select>
            </label>
            <button className="primary" type="submit" disabled={starting}>
              {starting ? '시작하는 중…' : '배포 시작'}
            </button>
          </>
        )}
        {startError && (
          <div className="notice error" role="alert">
            {startError}
          </div>
        )}
        <p className="axis-note" style={{ marginTop: 0 }}>
          1단계 그룹에 먼저 설치 지시가 나갑니다. 그 단계의 대상 PC가 모두 결과를 내고 오류율이 롤백 기준 이하이면 대기 시간 뒤에 다음 단계로 넘어가고,
          기준을 넘으면 롤백합니다. 서버가 자동으로 점검합니다.
        </p>
      </form>

      <h2 className="section-title">배포 현황</h2>
      {deployments.loading && <div className="notice">불러오는 중…</div>}
      {deployments.error && <div className="notice error">배포 현황을 불러오지 못했습니다. {deployments.error}</div>}
      {deployments.data && deployments.data.length === 0 && <div className="notice">아직 이 정책으로 시작한 배포가 없습니다.</div>}
      {deployments.data && deployments.data.length > 0 && (
        <>
          <ul className="legend" aria-label="PC 상태 범례">
            {STATUS_ORDER.map((key) => (
              <li key={key}>
                <span
                  className={`glyph${key === 'rolled_back' ? ' dark-text' : ''}`}
                  style={{ background: `var(--st-${key})` }}
                  aria-hidden="true"
                >
                  {STATUS_GLYPH[key]}
                </span>
                {STATUS_LABEL[key]}
              </li>
            ))}
          </ul>
          {anyRunning && <p className="axis-note">진행 중인 배포가 있어 {REFRESH_MS / 1000}초마다 자동으로 새로 고칩니다.</p>}
          <div className="deployments">
            {deployments.data.map((item) => (
              <DeploymentCard key={item.id} deployment={item} />
            ))}
          </div>
        </>
      )}
    </>
  )
}

const DEPLOYMENT_LABEL: Record<DeploymentState, { glyph: string; text: string; color: string }> = {
  running: { glyph: '▶', text: '진행 중', color: 'var(--accent)' },
  completed: { glyph: '✓', text: '완료', color: 'var(--st-applied)' },
  rolled_back: { glyph: '✕', text: '롤백됨', color: 'var(--st-error)' },
}

const STAGE_LABEL: Record<StageState, { glyph: string; text: string; color: string }> = {
  done: { glyph: '✓', text: '끝남', color: 'var(--st-applied)' },
  active: { glyph: '▶', text: '진행 중', color: 'var(--accent)' },
  waiting: { glyph: '…', text: '대기 중', color: 'var(--st-pending)' },
  failed: { glyph: '✕', text: '롤백 기준 초과', color: 'var(--st-error)' },
  upcoming: { glyph: '–', text: '실행 전', color: 'var(--st-pending)' },
}

function DeploymentCard({ deployment }: { deployment: DeploymentStatus }) {
  const tip = useTooltip()
  const label = DEPLOYMENT_LABEL[deployment.state]

  return (
    <section className="card deploy-card" aria-label={`${deployment.patch.kb_number} 배포`}>
      <div className="deploy-head">
        <div>
          <strong>{deployment.patch.kb_number}</strong> · {deployment.patch.target_os}
        </div>
        <span className="sev">
          <span className="glyph" style={{ background: label.color }} aria-hidden="true">
            {label.glyph}
          </span>
          {label.text}
        </span>
      </div>
      <div className="muted deploy-times">
        시작 {formatDateTime(deployment.started_at)}
        {deployment.finished_at ? ` · 끝 ${formatDateTime(deployment.finished_at)}` : ''}
      </div>
      {deployment.note && <div className="notice error">{deployment.note}</div>}

      <div className="stage-progress-list">
        {deployment.stages.map((stage) => (
          <StageRow key={stage.order} stage={stage} readyAt={stage.state === 'waiting' ? deployment.stage_ready_at : null} tip={tip} />
        ))}
      </div>
      {tip.element}
    </section>
  )
}

function StageRow({
  stage,
  readyAt,
  tip,
}: {
  stage: StageProgress
  readyAt: string | null
  tip: ReturnType<typeof useTooltip>
}) {
  const label = STAGE_LABEL[stage.state]
  const counts: Array<[keyof Pick<StageProgress, 'applied' | 'error' | 'rolled_back' | 'pending'>, string]> = [
    ['applied', 'applied'],
    ['error', 'error'],
    ['rolled_back', 'rolled_back'],
    ['pending', 'pending'],
  ]

  return (
    <div className="stage-progress">
      <div className="stage-progress-head">
        <span>
          <strong>{stage.order}단계</strong> · {stage.group_name}
        </span>
        <span className="sev">
          <span className="glyph" style={{ background: label.color }} aria-hidden="true">
            {label.glyph}
          </span>
          {label.text}
          {readyAt ? ` (${formatDateTime(readyAt).slice(11)}부터 설치)` : ''}
        </span>
      </div>
      {stage.target_count === 0 ? (
        <div className="stack-empty" aria-label="대상 PC 없음" />
      ) : (
        <div className="stack">
          {counts
            .filter(([key]) => stage[key] > 0)
            .map(([key, status]) => (
              <div
                key={key}
                className="seg"
                style={{ flexGrow: stage[key], background: `var(--st-${status})` }}
                {...tip.bind(`${stage.order}단계 ${STATUS_LABEL[status as keyof typeof STATUS_LABEL]}: ${stage[key]}대 (대상 ${stage.target_count}대)`)}
              />
            ))}
        </div>
      )}
      <div className="muted stage-meta">
        {stage.target_count === 0
          ? '이 그룹에는 패치의 대상 Windows인 PC가 없습니다.'
          : `대상 ${stage.target_count}대 · 적용 ${stage.applied} · 오류 ${stage.error} · 롤백 ${stage.rolled_back} · 미적용 ${stage.pending}`}
        {stage.target_count > 0 && (
          <>
            {' '}
            · 오류율 <strong>{formatPercent(stage.error_rate)}</strong> (롤백 기준 {formatPercent(stage.rollback_error_rate)} 초과 시)
          </>
        )}
        {stage.delay_minutes > 0 && ` · 이전 단계 후 ${stage.delay_minutes}분 대기`}
      </div>
    </div>
  )
}
