import { useState } from 'react'
import type { FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useApi } from '../api'
import type { AffectedSoftware, CveDetail, PatchDetail, SearchResult } from '../api'
import { SeverityBadge } from '../components/SeverityBadge'
import { formatDate } from '../labels'

const MIN_LENGTH = 2

export default function Search() {
  const [params, setParams] = useSearchParams()
  const query = (params.get('q') ?? '').trim()
  const [draft, setDraft] = useState(query)
  const [open, setOpen] = useState<string | null>(null) // 상세를 펼친 줄: 'cve-3' 같은 값

  const searchable = query.length >= MIN_LENGTH
  const { data, error, loading } = useApi<SearchResult>(
    searchable ? `/api/search/?q=${encodeURIComponent(query)}` : null,
  )

  function submit(event: FormEvent) {
    event.preventDefault()
    setOpen(null)
    setParams(draft.trim() ? { q: draft.trim() } : {})
  }

  const toggle = (key: string) => setOpen((current) => (current === key ? null : key))

  return (
    <main className="page">
      <h1>CVE · KB 검색</h1>
      <p className="lede">CVE 번호, KB 번호(숫자만도 가능) 또는 설명의 일부로 찾습니다. CVE 번호로 찾으면 그 CVE를 고치는 KB도 함께 나옵니다.</p>

      <form className="search-form" onSubmit={submit} role="search">
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="예: CVE-2024-43572, KB5044273, 5044273, log4j"
          aria-label="검색어"
          autoFocus
        />
        <button className="primary" type="submit">
          검색
        </button>
      </form>

      {!query && <div className="notice">검색어를 입력하세요.</div>}
      {query && !searchable && <div className="notice">검색어는 {MIN_LENGTH}글자 이상이어야 합니다.</div>}
      {loading && <div className="notice">찾는 중…</div>}
      {error && <div className="notice error">검색하지 못했습니다. {error}</div>}

      {data && (
        <>
          <h2 className="section-title">CVE ({data.cves.length}건)</h2>
          {data.cves.length === 0 ? (
            <div className="notice">일치하는 CVE가 없습니다.</div>
          ) : (
            <div className="card">
              <table>
                <thead>
                  <tr>
                    <th>CVE 번호</th>
                    <th>위험도</th>
                    <th className="num">점수</th>
                    <th>공개일</th>
                    <th>설명</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.cves.map((cve) => {
                    const key = `cve-${cve.id}`
                    return (
                      <RowWithDetail
                        key={key}
                        opened={open === key}
                        colSpan={6}
                        detail={<CveDetailPanel id={cve.id} />}
                      >
                        <td>{cve.cve_id}</td>
                        <td>
                          <SeverityBadge severity={cve.severity} />
                        </td>
                        <td className="num">{cve.cvss_score ?? '—'}</td>
                        <td className="nowrap">{formatDate(cve.published_at)}</td>
                        <td>{cve.description}</td>
                        <td>
                          <button className="link" onClick={() => toggle(key)} aria-expanded={open === key}>
                            {open === key ? '접기' : '상세'}
                          </button>
                        </td>
                      </RowWithDetail>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          <h2 className="section-title">패치 KB ({data.patches.length}건)</h2>
          {data.patches.length === 0 ? (
            <div className="notice">일치하는 KB가 없습니다.</div>
          ) : (
            <div className="card">
              <table>
                <thead>
                  <tr>
                    <th>KB 번호</th>
                    <th>대상 Windows</th>
                    <th>고쳐진 빌드</th>
                    <th>공개일</th>
                    <th className="num">해결하는 CVE</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.patches.map((patch) => {
                    const key = `patch-${patch.id}`
                    return (
                      <RowWithDetail
                        key={key}
                        opened={open === key}
                        colSpan={6}
                        detail={<PatchDetailPanel id={patch.id} />}
                      >
                        <td>{patch.kb_number}</td>
                        <td>{patch.target_os}</td>
                        <td>{patch.fixed_build || '—'}</td>
                        <td className="nowrap">{formatDate(patch.release_date)}</td>
                        <td className="num">{patch.cve_count}</td>
                        <td>
                          <button className="link" onClick={() => toggle(key)} aria-expanded={open === key}>
                            {open === key ? '접기' : '상세'}
                          </button>
                        </td>
                      </RowWithDetail>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </main>
  )
}

function RowWithDetail({
  opened,
  colSpan,
  detail,
  children,
}: {
  opened: boolean
  colSpan: number
  detail: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <>
      <tr>{children}</tr>
      {opened && (
        <tr>
          <td colSpan={colSpan}>{detail}</td>
        </tr>
      )}
    </>
  )
}

/** NVD의 버전 범위를 말로 풀어 쓴다 */
function rangeText(item: AffectedSoftware): string {
  if (item.version_exact) return `${item.version_exact} 버전`
  const parts = [
    item.version_start_including && `${item.version_start_including} 이상`,
    item.version_start_excluding && `${item.version_start_excluding} 초과`,
    item.version_end_including && `${item.version_end_including} 이하`,
    item.version_end_excluding && `${item.version_end_excluding} 미만`,
  ].filter(Boolean)
  return parts.length ? parts.join(', ') : '모든 버전'
}

function CveDetailPanel({ id }: { id: number }) {
  const { data, error, loading } = useApi<CveDetail>(`/api/cves/${id}/`)
  if (loading) return <div className="detail-panel">불러오는 중…</div>
  if (error || !data) return <div className="detail-panel">상세를 불러오지 못했습니다. {error}</div>
  return (
    <div className="detail-panel">
      <h3>설명</h3>
      <div>{data.description || '—'}</div>
      <h3>영향받는 소프트웨어</h3>
      {data.affected_software.length === 0 ? (
        <div className="muted">우리 소프트웨어 목록과 이어진 항목이 없습니다.</div>
      ) : (
        <ul>
          {data.affected_software.map((item) => (
            <li key={item.id}>
              {item.name} — {rangeText(item)}
            </li>
          ))}
        </ul>
      )}
      <h3>해결하는 KB</h3>
      {data.patches.length === 0 ? (
        <div className="muted">등록된 KB가 없습니다.</div>
      ) : (
        <ul>
          {data.patches.map((patch) => (
            <li key={patch.id}>
              {patch.kb_number} ({patch.target_os}
              {patch.fixed_build ? `, ${patch.fixed_build} 이상` : ''})
              {patch.download_url && (
                <>
                  {' '}
                  <a href={patch.download_url} target="_blank" rel="noreferrer">
                    내려받기
                  </a>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function PatchDetailPanel({ id }: { id: number }) {
  const { data, error, loading } = useApi<PatchDetail>(`/api/patches/${id}/`)
  if (loading) return <div className="detail-panel">불러오는 중…</div>
  if (error || !data) return <div className="detail-panel">상세를 불러오지 못했습니다. {error}</div>
  return (
    <div className="detail-panel">
      <h3>해결하는 CVE</h3>
      {data.cves.length === 0 ? (
        <div className="muted">연결된 CVE가 없습니다.</div>
      ) : (
        <ul>
          {data.cves.map((cve) => (
            <li key={cve.id}>
              {cve.cve_id} <SeverityBadge severity={cve.severity} />
              {cve.cvss_score ? ` ${cve.cvss_score}` : ''}
            </li>
          ))}
        </ul>
      )}
      <h3>기타</h3>
      <ul>
        <li>오류 보고된 패치: {data.is_error_reported ? '예' : '아니요'}</li>
        {data.download_url && (
          <li>
            <a href={data.download_url} target="_blank" rel="noreferrer">
              Microsoft Update Catalog에서 내려받기
            </a>
          </li>
        )}
      </ul>
    </div>
  )
}
