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
    throw new ApiError(response.status, detail || `요청에 실패했습니다 (HTTP ${response.status})`)
  }
  return response.json() as Promise<T>
}

export interface ApiState<T> {
  data: T | null
  error: string | null
  loading: boolean
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
