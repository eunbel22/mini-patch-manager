import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { sendJson, useApi } from '../api'
import type { Group, Paginated, Policy, PolicyInput } from '../api'
import { MIN_SEVERITY_OPTIONS, SEVERITY_ENGLISH, SEVERITY_LABEL } from '../labels'

interface StageForm {
  key: number // 줄을 구별하는 값(순서를 바꿔도 입력 칸이 섞이지 않게 한다)
  group: string
  delay: string
  percent: string // 롤백 오류율을 %로 입력한다
}

interface FormState {
  name: string
  minSeverity: Policy['min_severity']
  startTime: string
  isActive: boolean
  stages: StageForm[]
}

export default function PolicyEdit() {
  const { id } = useParams()
  const groups = useApi<Paginated<Group>>('/api/groups/')
  const existing = useApi<Policy>(id === undefined ? null : `/api/policies/${id}/`)

  const loading = groups.loading || existing.loading
  const error = groups.error ?? existing.error

  return (
    <main className="page">
      <p>
        <Link to="/policies">← 정책 목록</Link>
      </p>
      <h1>{id === undefined ? '새 정책' : '정책 편집'}</h1>
      {loading && <div className="notice">불러오는 중…</div>}
      {error && <div className="notice error">불러오지 못했습니다. {error}</div>}
      {groups.data && (id === undefined || existing.data) && (
        <PolicyForm key={id ?? 'new'} id={id} policy={existing.data} groups={groups.data.results} />
      )}
    </main>
  )
}

function toForm(policy: Policy | null, groups: Group[]): FormState {
  if (policy) {
    return {
      name: policy.name,
      minSeverity: policy.min_severity,
      startTime: policy.start_time ? policy.start_time.slice(0, 5) : '',
      isActive: policy.is_active,
      stages: [...policy.stages]
        .sort((a, b) => a.order - b.order)
        .map((stage, index) => ({
          key: index,
          group: String(stage.group),
          delay: String(stage.delay_minutes),
          percent: String(Number((stage.rollback_error_rate * 100).toFixed(2))),
        })),
    }
  }
  // 새 정책의 기본값: 테스트 그룹에 먼저, 1시간 뒤 일반 그룹에
  const find = (name: string) => String(groups.find((group) => group.name === name)?.id ?? groups[0]?.id ?? '')
  return {
    name: '',
    minSeverity: 'high',
    startTime: '',
    isActive: true,
    stages: [
      { key: 0, group: find('테스트'), delay: '0', percent: '10' },
      { key: 1, group: find('일반'), delay: '60', percent: '5' },
    ],
  }
}

function validate(form: FormState): string[] {
  const problems: string[] = []
  if (!form.name.trim()) problems.push('이름을 입력하세요.')
  if (form.stages.length === 0) problems.push('배포 단계를 하나 이상 넣으세요.')
  form.stages.forEach((stage, index) => {
    const label = `${index + 1}단계`
    if (!stage.group) problems.push(`${label}: 그룹을 고르세요.`)
    const delay = Number(stage.delay)
    if (stage.delay === '' || !Number.isInteger(delay) || delay < 0) problems.push(`${label}: 대기 시간은 0 이상의 정수(분)여야 합니다.`)
    const percent = Number(stage.percent)
    if (stage.percent === '' || Number.isNaN(percent) || percent < 0 || percent > 100) {
      problems.push(`${label}: 롤백 오류율은 0~100 사이여야 합니다.`)
    }
  })
  return problems
}

function PolicyForm({ id, policy, groups }: { id: string | undefined; policy: Policy | null; groups: Group[] }) {
  const navigate = useNavigate()
  const [form, setForm] = useState<FormState>(() => toForm(policy, groups))
  const [attempted, setAttempted] = useState(false) // 저장을 한 번 시도한 뒤에는 입력할 때마다 바로 다시 검사한다
  const [serverError, setServerError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const nextKey = useRef(100)
  const problems = attempted ? validate(form) : []

  const setStage = (key: number, changes: Partial<StageForm>) =>
    setForm((current) => ({
      ...current,
      stages: current.stages.map((stage) => (stage.key === key ? { ...stage, ...changes } : stage)),
    }))

  function addStage() {
    setForm((current) => ({
      ...current,
      stages: [...current.stages, { key: nextKey.current++, group: String(groups[0]?.id ?? ''), delay: '60', percent: '5' }],
    }))
  }

  function removeStage(key: number) {
    setForm((current) => ({ ...current, stages: current.stages.filter((stage) => stage.key !== key) }))
  }

  function move(index: number, step: -1 | 1) {
    setForm((current) => {
      const stages = [...current.stages]
      const target = index + step
      if (target < 0 || target >= stages.length) return current
      ;[stages[index], stages[target]] = [stages[target], stages[index]]
      return { ...current, stages }
    })
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setAttempted(true)
    setServerError(null)
    if (validate(form).length > 0) return

    const input: PolicyInput = {
      name: form.name.trim(),
      min_severity: form.minSeverity,
      start_time: form.startTime || null,
      is_active: form.isActive,
      // 위에서 아래 순서가 곧 배포 순서다
      stages: form.stages.map((stage, index) => ({
        order: index + 1,
        group: Number(stage.group),
        delay_minutes: Number(stage.delay),
        rollback_error_rate: Number((Number(stage.percent) / 100).toFixed(4)),
      })),
    }
    setSaving(true)
    try {
      await sendJson<Policy>(id === undefined ? 'POST' : 'PUT', id === undefined ? '/api/policies/' : `/api/policies/${id}/`, input)
      navigate('/policies')
    } catch (error) {
      setServerError(error instanceof Error ? error.message : '저장하지 못했습니다.')
      setSaving(false)
    }
  }

  return (
    <form className="card form" onSubmit={submit} noValidate>
      <div className="form-grid">
        <label className="field">
          <span>이름</span>
          <input
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            placeholder="예: 높음 이상 단계 배포"
            maxLength={100}
          />
        </label>
        <label className="field">
          <span>대상 패치: 최소 위험도</span>
          <select
            value={form.minSeverity}
            onChange={(event) => setForm({ ...form, minSeverity: event.target.value as Policy['min_severity'] })}
          >
            {MIN_SEVERITY_OPTIONS.map((key) => (
              <option key={key} value={key}>
                {SEVERITY_LABEL[key]} ({SEVERITY_ENGLISH[key]}) 이상
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>실행 시각 (선택)</span>
          <input type="time" value={form.startTime} onChange={(event) => setForm({ ...form, startTime: event.target.value })} />
        </label>
        <label className="field checkbox">
          <input type="checkbox" checked={form.isActive} onChange={(event) => setForm({ ...form, isActive: event.target.checked })} />
          <span>사용</span>
        </label>
      </div>

      <h2 className="section-title">배포 단계</h2>
      <p className="axis-note" style={{ marginTop: 0 }}>
        위에서 아래 순서로 배포합니다. 보통 1단계는 테스트 그룹이고 마지막 단계는 전체에 가까운 그룹입니다. 이전 단계가 끝나고 대기 시간이 지나면 다음 단계로 넘어가며, 한 단계의 오류율이 롤백 오류율을 넘으면 롤백합니다.
      </p>

      <div className="stages">
        <div className="stage-row stage-head" aria-hidden="true">
          <span>단계</span>
          <span>그룹</span>
          <span>이전 단계 후 대기(분)</span>
          <span>롤백 오류율(%)</span>
          <span />
        </div>
        {form.stages.map((stage, index) => (
          <div className="stage-row" key={stage.key}>
            <span className="stage-no">{index + 1}단계</span>
            <select
              aria-label={`${index + 1}단계 그룹`}
              value={stage.group}
              onChange={(event) => setStage(stage.key, { group: event.target.value })}
            >
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </select>
            <input
              aria-label={`${index + 1}단계 대기 시간(분)`}
              type="number"
              min={0}
              step={1}
              value={stage.delay}
              onChange={(event) => setStage(stage.key, { delay: event.target.value })}
            />
            <input
              aria-label={`${index + 1}단계 롤백 오류율(%)`}
              type="number"
              min={0}
              max={100}
              step="any"
              value={stage.percent}
              onChange={(event) => setStage(stage.key, { percent: event.target.value })}
            />
            <span className="stage-actions">
              <button type="button" onClick={() => move(index, -1)} disabled={index === 0} aria-label={`${index + 1}단계를 위로`}>
                ↑
              </button>
              <button
                type="button"
                onClick={() => move(index, 1)}
                disabled={index === form.stages.length - 1}
                aria-label={`${index + 1}단계를 아래로`}
              >
                ↓
              </button>
              <button type="button" onClick={() => removeStage(stage.key)} aria-label={`${index + 1}단계 삭제`}>
                삭제
              </button>
            </span>
          </div>
        ))}
      </div>
      <p>
        <button type="button" onClick={addStage}>
          + 단계 추가
        </button>
      </p>

      {problems.length > 0 && (
        <div className="notice error" role="alert">
          <strong>저장하기 전에 확인하세요.</strong>
          <ul>
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </div>
      )}
      {serverError && (
        <div className="notice error" role="alert">
          저장하지 못했습니다. {serverError}
        </div>
      )}

      <div className="form-actions">
        <button className="primary" type="submit" disabled={saving}>
          {saving ? '저장 중…' : '저장'}
        </button>
        <Link className="btn" to="/policies">
          취소
        </Link>
      </div>
      <p className="axis-note">저장한 뒤 정책 상세 화면에서 패치를 골라 배포를 시작합니다. 진행 중인 배포가 있으면 배포 단계는 바꿀 수 없습니다.</p>
    </form>
  )
}
