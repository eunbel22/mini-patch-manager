import { useEffect, useState } from 'react'

// ---- 서버 응답 모양 (backend/patchmgr/serializers.py와 services.py가 만드는 값) ----

export type StatusKey = 'applied' | 'pending' | 'error' | 'rolled_back'
export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'unscored'

export interface DashboardSummary {
  patch_rate: number | null
  total: number
  status_counts: Record<StatusKey, number>
  endpoint_count: number
  reported_endpoint_count: number
  software_vulnerable_endpoints_by_severity: Record<SeverityKey, number>
  unknown_assessments: number
  running_deployments: number
}

export interface CveHit {
  id: number
  cve_id: string
  severity: string
  cvss_score: string | null
  published_at: string | null
  description: string
}

export interface PatchHit {
  id: number
  kb_number: string
  target_os: string
  fixed_build: string
  release_date: string | null
  cve_count: number
}

export interface SearchResult {
  cves: CveHit[]
  patches: PatchHit[]
}

export interface AffectedSoftware {
  id: number
  name: string
  vendor: string
  version_start_including: string
  version_start_excluding: string
  version_end_including: string
  version_end_excluding: string
  version_exact: string
}

export interface PatchSummary {
  id: number
  kb_number: string
  target_os: string
  fixed_build: string
  download_url: string
}

export interface CveDetail extends CveHit {
  affected_software: AffectedSoftware[]
  patches: PatchSummary[]
}

export interface CveSummary {
  id: number
  cve_id: string
  cvss_score: string | null
  severity: string
}

export interface PatchDetail {
  id: number
  kb_number: string
  title: string
  target_os: string
  fixed_build: string
  release_date: string | null
  download_url: string
  is_error_reported: boolean
  cves: CveSummary[]
}

export interface Paginated<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface Group {
  id: number
  name: string
}

export interface EndpointRow {
  id: number
  hostname: string
  os_name: string
  os_build: string
  group: number
  group_name: string
  last_reported_at: string | null
  unapplied_patch_count: number
  error_patch_count: number
  vulnerable_cve_count: number
}

export interface InstalledSoftwareRow {
  id: number
  name: string
  vendor: string
  version: string
}

export interface PatchStatusRow {
  id: number
  patch: number
  kb_number: string
  target_os: string
  status: StatusKey
  error_code: string
  reported_at: string | null
}

export interface Vulnerability {
  cve_id: string
  severity: string
  cvss_score: string | null
  software: string
  installed_version: string
  status: 'vulnerable' | 'unknown'
}

export interface EndpointDetail {
  id: number
  hostname: string
  os_name: string
  os_build: string
  group: number
  group_name: string
  last_reported_at: string | null
  installed_software: InstalledSoftwareRow[]
  patch_statuses: PatchStatusRow[]
  vulnerabilities: Vulnerability[]
}

export interface PolicyStage {
  id?: number
  order: number
  group: number
  delay_minutes: number
  rollback_error_rate: number // 0.0 ~ 1.0
}

export interface Policy {
  id: number
  name: string
  min_severity: 'low' | 'medium' | 'high' | 'critical'
  start_time: string | null // "HH:MM:SS"
  is_active: boolean
  stages: PolicyStage[]
}

export type PolicyInput = Omit<Policy, 'id' | 'stages'> & { stages: Omit<PolicyStage, 'id'>[] }

export type StageState = 'done' | 'active' | 'waiting' | 'failed' | 'upcoming'
export type DeploymentState = 'running' | 'completed' | 'rolled_back'

/** 배포 한 건의 단계 하나: 대상 PC 수와 상태별 수, 오류율 */
export interface StageProgress {
  order: number
  group: number
  group_name: string
  delay_minutes: number
  rollback_error_rate: number // 0.0 ~ 1.0
  state: StageState
  target_count: number
  applied: number
  error: number
  pending: number
  rolled_back: number
  error_rate: number // 0.0 ~ 1.0
}

export interface DeploymentStatus {
  id: number
  policy: number
  patch: { id: number; kb_number: string; target_os: string }
  state: DeploymentState
  current_stage_order: number | null
  stage_ready_at: string | null
  started_at: string
  finished_at: string | null
  note: string
  stages: StageProgress[]
}

/** 배포할 패치를 고르는 목록의 한 줄 */
export interface PatchOption {
  id: number
  kb_number: string
  target_os: string
  fixed_build: string
  release_date: string | null
  is_error_reported: boolean
  max_severity: string
}

// ---- 요청 ----

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(url, { signal, headers: { Accept: 'application/json' } })
  if (!response.ok) {
    let detail = ''
    try {
      detail = (await response.json()).detail ?? ''
    } catch {
      // 본문이 JSON이 아니면 기본 문구를 쓴다
    }
    // 404는 서버가 영어 문구를 보내므로(Invalid page. 등) 한국어로 바꿔 보여 준다
    if (response.status === 404) detail = '요청한 항목(또는 쪽)을 찾을 수 없습니다.'
    throw new ApiError(response.status, detail || `요청에 실패했습니다 (HTTP ${response.status})`)
  }
  return response.json() as Promise<T>
}

// 서버가 돌려주는 입력 오류의 칸 이름을 한국어로 바꿔 보여 준다
const FIELD_LABEL: Record<string, string> = {
  name: '이름',
  min_severity: '최소 위험도',
  start_time: '실행 시각',
  is_active: '사용 여부',
  stages: '배포 단계',
  order: '순서',
  group: '그룹',
  delay_minutes: '대기 시간',
  rollback_error_rate: '롤백 오류율',
}

function flattenErrors(value: unknown, field = ''): string[] {
  if (typeof value === 'string') return [field ? `${FIELD_LABEL[field] ?? field}: ${value}` : value]
  if (Array.isArray(value)) return value.flatMap((item) => flattenErrors(item, field))
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, inner]) =>
      flattenErrors(inner, /^\d+$/.test(key) ? field : key), // 배열 위치(0, 1, ...)는 칸 이름으로 쓰지 않는다
    )
  }
  return []
}

/** 저장(POST) · 수정(PUT) · 삭제(DELETE). 성공하면 서버가 돌려준 값을 주고, 삭제처럼 값이 없으면 null을 준다. */
export async function sendJson<T>(method: 'POST' | 'PUT' | 'DELETE', url: string, body?: unknown): Promise<T | null> {
  const response = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let data: unknown = null
    try {
      data = await response.json()
    } catch {
      // 본문이 JSON이 아니면 기본 문구를 쓴다
    }
    const message = response.status === 404 ? '요청한 항목을 찾을 수 없습니다.' : flattenErrors(data).join(' / ')
    throw new ApiError(response.status, message || `요청에 실패했습니다 (HTTP ${response.status})`)
  }
  return response.status === 204 ? null : (response.json() as Promise<T>)
}

export interface ApiState<T> {
  data: T | null
  error: string | null
  loading: boolean
}

/** 일정한 간격으로 다시 불러온다. 새로 불러오는 동안에도 이전 값을 그대로 보여 줘서 화면이 깜빡이지 않는다. */
export function usePolling<T>(url: string, intervalMs: number): ApiState<T> & { reload: () => void } {
  const [settled, setSettled] = useState<{ url: string; data: T | null; error: string | null } | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    getJson<T>(url, controller.signal)
      .then((data) => setSettled({ url, data, error: null }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return
        const message = error instanceof Error ? error.message : '알 수 없는 오류'
        setSettled((previous) => ({ url, data: previous && previous.url === url ? previous.data : null, error: message }))
      })
    return () => controller.abort()
  }, [url, tick])

  useEffect(() => {
    const timer = window.setInterval(() => setTick((value) => value + 1), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])

  const current = settled && settled.url === url ? settled : null
  return {
    data: current?.data ?? null,
    error: current?.error ?? null,
    loading: current === null,
    reload: () => setTick((value) => value + 1),
  }
}

interface Settled<T> {
  url: string
  data: T | null
  error: string | null
}

/** url이 null이면 요청하지 않는다. url이 바뀌면 이전 요청은 취소한다. */
export function useApi<T>(url: string | null): ApiState<T> {
  // 응답이 어느 주소의 것인지 함께 저장해 두면, "불러오는 중"인지는 상태를 따로 바꾸지 않고 계산할 수 있다
  const [settled, setSettled] = useState<Settled<T> | null>(null)

  useEffect(() => {
    if (url === null) return
    const controller = new AbortController()
    getJson<T>(url, controller.signal)
      .then((data) => setSettled({ url, data, error: null }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return
        setSettled({ url, data: null, error: error instanceof Error ? error.message : '알 수 없는 오류' })
      })
    return () => controller.abort()
  }, [url])

  if (url === null) return { data: null, error: null, loading: false }
  if (settled === null || settled.url !== url) return { data: null, error: null, loading: true }
  return { data: settled.data, error: settled.error, loading: false }
}
