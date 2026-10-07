import type { StatusKey } from '../api'
import { STATUS_GLYPH, STATUS_LABEL } from '../labels'

/** 패치 상태 표시: 색 상자 + 아이콘 글자 + 이름 (색만으로 구분하지 않는다) */
export function StatusChip({ status }: { status: StatusKey }) {
  return (
    <span className="sev">
      <span
        className={`glyph${status === 'rolled_back' ? ' dark-text' : ''}`}
        style={{ background: `var(--st-${status})` }}
        aria-hidden="true"
      >
        {STATUS_GLYPH[status]}
      </span>
      {STATUS_LABEL[status]}
    </span>
  )
}
