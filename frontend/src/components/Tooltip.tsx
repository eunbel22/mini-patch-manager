import { useState } from 'react'
import type { FocusEvent, MouseEvent, ReactNode } from 'react'

interface TooltipState {
  x: number
  y: number
  text: string
}

/** 막대 한 조각 위에 마우스를 올리거나 키보드로 이동하면 값을 보여 주는 설명 상자 */
export function useTooltip(): {
  bind: (text: string) => Record<string, unknown>
  element: ReactNode
} {
  const [tip, setTip] = useState<TooltipState | null>(null)

  const bind = (text: string) => ({
    tabIndex: 0,
    'aria-label': text,
    onMouseEnter: (event: MouseEvent) => setTip({ x: event.clientX, y: event.clientY, text }),
    onMouseMove: (event: MouseEvent) => setTip({ x: event.clientX, y: event.clientY, text }),
    onMouseLeave: () => setTip(null),
    onFocus: (event: FocusEvent<HTMLElement>) => {
      const box = event.currentTarget.getBoundingClientRect()
      setTip({ x: box.left + box.width / 2, y: box.top, text })
    },
    onBlur: () => setTip(null),
  })

  const element = tip ? (
    <div className="tooltip" role="tooltip" style={{ left: tip.x + 12, top: tip.y + 12 }}>
      {tip.text}
    </div>
  ) : null

  return { bind, element }
}
