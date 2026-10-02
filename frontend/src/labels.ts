import type { SeverityKey, StatusKey } from './api'

// 위험도는 CVSS 3.1 등급: 낮음(Low) 0.1~3.9, 보통(Medium) 4.0~6.9, 높음(High) 7.0~8.9, 매우 높음(Critical) 9.0~10.0
export const SEVERITY_ORDER: SeverityKey[] = ['critical', 'high', 'medium', 'low', 'unscored']

export const SEVERITY_LABEL: Record<SeverityKey, string> = {
  critical: '매우 높음',
  high: '높음',
  medium: '보통',
  low: '낮음',
  unscored: '점수 없음',
}

export const SEVERITY_ENGLISH: Record<SeverityKey, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unscored: 'Unscored',
}

export function severityKey(value: string): SeverityKey {
  return value === 'critical' || value === 'high' || value === 'medium' || value === 'low' ? value : 'unscored'
}

export const STATUS_ORDER: StatusKey[] = ['applied', 'pending', 'error', 'rolled_back']

export const STATUS_LABEL: Record<StatusKey, string> = {
  applied: '적용',
  pending: '미적용',
  error: '오류',
  rolled_back: '롤백',
}

// 상태는 색만으로 구분하지 않도록 아이콘 글자를 함께 쓴다
export const STATUS_GLYPH: Record<StatusKey, string> = {
  applied: '✓',
  pending: '…',
  error: '✕',
  rolled_back: '↩',
}

export function formatPercent(rate: number): string {
  const percent = rate * 100
  return `${Number.isInteger(percent) ? percent : percent.toFixed(1)}%`
}

export function formatDate(iso: string | null): string {
  return iso ? iso.slice(0, 10) : '—'
}
