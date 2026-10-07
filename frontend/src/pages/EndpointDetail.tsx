import { Link, useParams } from 'react-router-dom'
import { useApi } from '../api'
import type { EndpointDetail as EndpointDetailData, Vulnerability } from '../api'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusChip } from '../components/StatusChip'
import { formatDateTime } from '../labels'

export default function EndpointDetail() {
  const { id } = useParams()
  const { data, error, loading } = useApi<EndpointDetailData>(`/api/endpoints/${id}/`)

  return (
    <main className="page">
      <p>
        <Link to="/endpoints">← PC 목록</Link>
      </p>
      {loading && <div className="notice">불러오는 중…</div>}
      {error && <div className="notice error">PC를 불러오지 못했습니다. {error}</div>}
      {data && <Detail data={data} />}
    </main>
  )
}

function Detail({ data }: { data: EndpointDetailData }) {
  const vulnerable = data.vulnerabilities.filter((item) => item.status === 'vulnerable').length
  const unknown = data.vulnerabilities.length - vulnerable

  return (
    <>
      <h1>{data.hostname}</h1>
      <p className="lede">
        {data.group_name} 그룹 · {data.os_name} · 빌드 {data.os_build} · 마지막 보고 {formatDateTime(data.last_reported_at)}
      </p>

      <h2 className="section-title">
        취약점 판단 (취약 {vulnerable}건{unknown > 0 ? `, 판단 불가 ${unknown}건` : ''})
      </h2>
      <p className="axis-note" style={{ marginTop: 0 }}>
        설치된 소프트웨어 버전이 CVE의 영향 범위에 들어가는지 비교한 결과입니다. 버전을 읽지 못하면 판단 불가로 따로 표시합니다.
      </p>
      {data.vulnerabilities.length === 0 ? (
        <div className="notice">영향 범위에 드는 CVE가 없습니다.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>CVE 번호</th>
                <th>위험도</th>
                <th className="num">점수</th>
                <th>소프트웨어</th>
                <th>설치된 버전</th>
                <th>판단</th>
              </tr>
            </thead>
            <tbody>
              {data.vulnerabilities.map((item) => (
                <tr key={`${item.cve_id}-${item.software}`}>
                  <td>
                    <Link to={`/search?q=${encodeURIComponent(item.cve_id)}`}>{item.cve_id}</Link>
                  </td>
                  <td>
                    <SeverityBadge severity={item.severity} />
                  </td>
                  <td className="num">{item.cvss_score ?? '—'}</td>
                  <td>{item.software}</td>
                  <td>{item.installed_version}</td>
                  <td>
                    <Judgement status={item.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 className="section-title">패치 상태 ({data.patch_statuses.length}건)</h2>
      {data.patch_statuses.length === 0 ? (
        <div className="notice">이 PC의 Windows에 해당하는 패치 보고가 없습니다.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>KB 번호</th>
                <th>대상 Windows</th>
                <th>상태</th>
                <th>오류 코드</th>
                <th>보고 시각</th>
              </tr>
            </thead>
            <tbody>
              {data.patch_statuses.map((item) => (
                <tr key={item.id}>
                  <td>
                    <Link to={`/search?q=${encodeURIComponent(item.kb_number)}`}>{item.kb_number}</Link>
                  </td>
                  <td>{item.target_os}</td>
                  <td>
                    <StatusChip status={item.status} />
                  </td>
                  <td>{item.error_code || '—'}</td>
                  <td className="nowrap">{formatDateTime(item.reported_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 className="section-title">설치된 소프트웨어 ({data.installed_software.length}종)</h2>
      {data.installed_software.length === 0 ? (
        <div className="notice">보고된 소프트웨어가 없습니다.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>이름</th>
                <th>제조사</th>
                <th>버전</th>
              </tr>
            </thead>
            <tbody>
              {data.installed_software.map((item) => (
                <tr key={item.id}>
                  <td>{item.name}</td>
                  <td>{item.vendor || '—'}</td>
                  <td>{item.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

/** 취약은 ✕, 판단 불가는 ? 아이콘을 함께 쓴다 */
function Judgement({ status }: { status: Vulnerability['status'] }) {
  const vulnerable = status === 'vulnerable'
  return (
    <span className="sev">
      <span
        className="glyph"
        style={{ background: vulnerable ? 'var(--st-error)' : 'var(--st-pending)' }}
        aria-hidden="true"
      >
        {vulnerable ? '✕' : '?'}
      </span>
      {vulnerable ? '취약' : '판단 불가'}
    </span>
  )
}
