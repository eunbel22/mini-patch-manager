import { SEVERITY_ENGLISH, SEVERITY_LABEL, severityKey } from '../labels'

/** 위험도 표시: 색 점과 글자를 함께 쓴다 (색만으로 구분하지 않는다) */
export function SeverityBadge({ severity }: { severity: string }) {
  const key = severityKey(severity)
  return (
    <span className="sev" title={SEVERITY_ENGLISH[key]}>
      <span className="sev-dot" style={{ background: `var(--sev-${key})` }} aria-hidden="true" />
      {SEVERITY_LABEL[key]}
    </span>
  )
}
