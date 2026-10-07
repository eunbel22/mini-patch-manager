import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useApi } from '../api'
import type { EndpointRow, Group, Paginated } from '../api'
import { STATUS_LABEL, STATUS_ORDER, formatDateTime } from '../labels'

const PAGE_SIZE = 50 // 서버(Django REST framework)가 한 쪽에 주는 개수

export default function Endpoints() {
  const [params, setParams] = useSearchParams()
  const group = params.get('group') ?? ''
  const status = params.get('status') ?? ''
  const search = params.get('search') ?? ''
  const page = Math.max(1, Number(params.get('page')) || 1)
  const [draft, setDraft] = useState(search)

  const groups = useApi<Paginated<Group>>('/api/groups/')

  const query = new URLSearchParams()
  if (group) query.set('group', group)
  if (status) query.set('status', status)
  if (search) query.set('search', search)
  if (page > 1) query.set('page', String(page))
  const { data, error, loading } = useApi<Paginated<EndpointRow>>(`/api/endpoints/?${query}`)

  // 필터가 바뀌면 1쪽부터 다시 본다
  function update(changes: Record<string, string>) {
    const next = new URLSearchParams(params)
    next.delete('page')
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value)
      else next.delete(key)
    }
    setParams(next)
  }

  function goToPage(target: number) {
    const next = new URLSearchParams(params)
    if (target > 1) next.set('page', String(target))
    else next.delete('page')
    setParams(next)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    update({ search: draft.trim() })
  }

  function reset() {
    setDraft('')
    setParams({})
  }

  const hasFilter = Boolean(group || status || search)
  const totalPages = data ? Math.max(1, Math.ceil(data.count / PAGE_SIZE)) : 1
  const first = data && data.count > 0 ? (page - 1) * PAGE_SIZE + 1 : 0
  const last = data ? first + data.results.length - (data.results.length ? 1 : 0) : 0

  return (
    <main className="page">
      <h1>PC 목록</h1>
      <p className="lede">PC마다 아직 적용하지 않은 패치, 오류가 난 패치, 설치된 소프트웨어가 걸리는 CVE의 수를 보여 줍니다. 호스트 이름을 누르면 상세가 열립니다.</p>

      <form className="filters" onSubmit={submit} role="search">
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="호스트 이름 (예: pc-01)"
          aria-label="호스트 이름 검색"
        />
        <button type="submit">검색</button>
        <label>
          그룹{' '}
          <select value={group} onChange={(event) => update({ group: event.target.value })}>
            <option value="">전체</option>
            {groups.data?.results.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          패치 상태{' '}
          <select value={status} onChange={(event) => update({ status: event.target.value })}>
            <option value="">전체</option>
            {STATUS_ORDER.map((key) => (
              <option key={key} value={key}>
                {STATUS_LABEL[key]}
              </option>
            ))}
          </select>
        </label>
        {hasFilter && (
          <button type="button" className="link" onClick={reset}>
            필터 초기화
          </button>
        )}
      </form>
      {status && <p className="axis-note">"{STATUS_LABEL[status as keyof typeof STATUS_LABEL] ?? status}" 상태인 패치가 하나라도 있는 PC만 보여 줍니다.</p>}

      {loading && <div className="notice">불러오는 중…</div>}
      {error && (
        <div className="notice error">
          목록을 불러오지 못했습니다. {error}{' '}
          {page > 1 && (
            <button className="link" onClick={() => goToPage(1)}>
              첫 쪽으로
            </button>
          )}
        </div>
      )}

      {data && data.count === 0 && <div className="notice">조건에 맞는 PC가 없습니다.</div>}

      {data && data.count > 0 && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>호스트 이름</th>
                <th>그룹</th>
                <th>Windows</th>
                <th>빌드</th>
                <th className="num">미적용 패치</th>
                <th className="num">오류</th>
                <th className="num">취약한 CVE</th>
                <th>마지막 보고</th>
              </tr>
            </thead>
            <tbody>
              {data.results.map((row) => (
                <tr key={row.id}>
                  <td>
                    <Link to={`/endpoints/${row.id}`}>{row.hostname}</Link>
                  </td>
                  <td>{row.group_name}</td>
                  <td>{row.os_name}</td>
                  <td>{row.os_build}</td>
                  <td className="num">{row.unapplied_patch_count}</td>
                  <td className={`num${row.error_patch_count > 0 ? ' strong' : ''}`}>{row.error_patch_count}</td>
                  <td className={`num${row.vulnerable_cve_count > 0 ? ' strong' : ''}`}>{row.vulnerable_cve_count}</td>
                  <td className="nowrap">{formatDateTime(row.last_reported_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="pager">
            <span className="muted">
              {data.count.toLocaleString()}대 중 {first.toLocaleString()}–{last.toLocaleString()}
            </span>
            <span className="pager-buttons">
              <button disabled={page <= 1} onClick={() => goToPage(page - 1)}>
                이전
              </button>
              <span>
                {page} / {totalPages}쪽
              </span>
              <button disabled={page >= totalPages} onClick={() => goToPage(page + 1)}>
                다음
              </button>
            </span>
          </div>
        </div>
      )}
    </main>
  )
}
