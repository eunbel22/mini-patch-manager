import { useApi } from '../api'
import type { DashboardSummary } from '../api'
import { useTooltip } from '../components/Tooltip'
import {
  SEVERITY_ENGLISH,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  STATUS_GLYPH,
  STATUS_LABEL,
  STATUS_ORDER,
  formatPercent,
} from '../labels'

export default function Dashboard() {
  const { data, error, loading } = useApi<DashboardSummary>('/api/dashboard/summary/')

  return (
    <main className="page">
      <h1>대시보드</h1>
      <p className="lede">PC들의 패치 적용 현황과 설치된 소프트웨어의 취약 현황입니다.</p>
      {loading && <div className="notice">불러오는 중…</div>}
      {error && <div className="notice error">대시보드를 불러오지 못했습니다. {error}</div>}
      {data && <Summary data={data} />}
    </main>
  )
}

function Summary({ data }: { data: DashboardSummary }) {
  const statusTip = useTooltip()
  const severityTip = useTooltip()

  const total = data.total
  const maxSeverity = Math.max(1, ...SEVERITY_ORDER.map((key) => data.software_vulnerable_endpoints_by_severity[key]))

  return (
    <div className="grid">
      <section className="card span-6" aria-labelledby="rate-title">
        <h2 id="rate-title">패치율</h2>
        <p className="sub">적용된 건수 ÷ 전체 건수 (PC와 패치 한 쌍이 한 건)</p>
        {data.patch_rate === null ? (
          <>
            <div className="hero">
              <span className="hero-value">—</span>
            </div>
            <p className="hero-caption">아직 에이전트 보고가 없습니다.</p>
          </>
        ) : (
          <>
            <div className="hero">
              <span className="hero-value">{formatPercent(data.patch_rate)}</span>
              <span className="hero-caption">
                적용 {data.status_counts.applied.toLocaleString()}건 / 전체 {total.toLocaleString()}건
              </span>
            </div>
            <div
              className="meter"
              role="meter"
              aria-label="패치율"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(data.patch_rate * 100)}
            >
              <div className="meter-fill" style={{ width: `${data.patch_rate * 100}%` }} />
            </div>
          </>
        )}
      </section>

      <section className="card span-6" aria-labelledby="coverage-title">
        <h2 id="coverage-title">보고 현황</h2>
        <p className="sub">서버에 상태를 보고한 PC</p>
        <div className="kpi-value">
          {data.reported_endpoint_count.toLocaleString()} / {data.endpoint_count.toLocaleString()}대
        </div>
        <div className="kpi-label">보고한 PC / 전체 PC</div>
        <div className="kpi-value" style={{ marginTop: 14 }}>
          {data.unknown_assessments.toLocaleString()}건
        </div>
        <div className="kpi-label">판단 불가 (설치된 버전을 읽지 못해 취약 여부를 알 수 없는 건, 취약으로 세지 않음)</div>
      </section>

      <section className="card span-12" aria-labelledby="status-title">
        <h2 id="status-title">패치 상태별 건수</h2>
        <p className="sub">전체 {total.toLocaleString()}건의 상태 분포</p>
        {total === 0 ? (
          <div className="stack-empty" aria-label="데이터 없음" />
        ) : (
          <div className="stack">
            {STATUS_ORDER.filter((key) => data.status_counts[key] > 0).map((key) => {
              const count = data.status_counts[key]
              const text = `${STATUS_LABEL[key]}: ${count.toLocaleString()}건 (${formatPercent(count / total)})`
              return (
                <div
                  key={key}
                  className="seg"
                  style={{ flexGrow: count, background: `var(--st-${key})` }}
                  {...statusTip.bind(text)}
                />
              )
            })}
          </div>
        )}
        <ul className="legend">
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
              <span className="count">{data.status_counts[key].toLocaleString()}</span>
            </li>
          ))}
        </ul>
        {statusTip.element}
      </section>

      <section className="card span-12" aria-labelledby="severity-title">
        <h2 id="severity-title">위험도별 취약한 PC</h2>
        <p className="sub">설치된 소프트웨어 버전이 CVE의 영향 범위에 들어가는 PC 수</p>
        <div className="hbars">
          {SEVERITY_ORDER.map((key) => {
            const value = data.software_vulnerable_endpoints_by_severity[key]
            const text = `${SEVERITY_LABEL[key]} (${SEVERITY_ENGLISH[key]}): ${value.toLocaleString()}대`
            return (
              <div className="hbar" key={key}>
                <span className="hbar-label">{SEVERITY_LABEL[key]}</span>
                <span className="hbar-track">
                  <span
                    className="hbar-bar"
                    style={{
                      width: `calc((100% - 56px) * ${value / maxSeverity})`,
                      background: `var(--sev-${key})`,
                      minWidth: value === 0 ? 0 : undefined, // 값이 0이면 막대를 그리지 않는다
                    }}
                    {...severityTip.bind(text)}
                  />
                  <span className="hbar-value">{value.toLocaleString()}대</span>
                </span>
              </div>
            )
          })}
        </div>
        <p className="axis-note">한 PC가 여러 등급의 CVE에 걸리면 등급마다 한 번씩 셉니다.</p>
        {severityTip.element}

        <details className="table-view">
          <summary>표로 보기</summary>
          <table>
            <thead>
              <tr>
                <th>위험도</th>
                <th className="num">취약한 PC</th>
              </tr>
            </thead>
            <tbody>
              {SEVERITY_ORDER.map((key) => (
                <tr key={key}>
                  <td>
                    {SEVERITY_LABEL[key]} ({SEVERITY_ENGLISH[key]})
                  </td>
                  <td className="num">{data.software_vulnerable_endpoints_by_severity[key].toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table>
            <thead>
              <tr>
                <th>패치 상태</th>
                <th className="num">건수</th>
              </tr>
            </thead>
            <tbody>
              {STATUS_ORDER.map((key) => (
                <tr key={key}>
                  <td>{STATUS_LABEL[key]}</td>
                  <td className="num">{data.status_counts[key].toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </section>
    </div>
  )
}
