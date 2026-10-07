import { useState } from 'react'
import { Link } from 'react-router-dom'
import { sendJson, useApi } from '../api'
import type { Group, Paginated, Policy } from '../api'
import { SeverityBadge } from '../components/SeverityBadge'

export default function Policies() {
  const [reload, setReload] = useState(0) // 삭제한 뒤 목록을 다시 불러오려고 주소에 붙이는 값
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const policies = useApi<Paginated<Policy>>(`/api/policies/?r=${reload}`)
  const groups = useApi<Paginated<Group>>('/api/groups/')

  const groupName = new Map((groups.data?.results ?? []).map((group) => [group.id, group.name]))

  async function remove(policy: Policy) {
    if (!window.confirm(`"${policy.name}" 정책을 삭제할까요? 되돌릴 수 없습니다.`)) return
    setDeleteError(null)
    try {
      await sendJson('DELETE', `/api/policies/${policy.id}/`)
      setReload((value) => value + 1)
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : '삭제하지 못했습니다.')
    }
  }

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>정책</h1>
          <p className="lede">패치를 어느 그룹에 어떤 순서로 배포할지 정합니다. 1단계(보통 테스트 그룹)에서 이상이 없으면 다음 단계로 넘어갑니다.</p>
        </div>
        <Link className="btn primary" to="/policies/new">
          새 정책
        </Link>
      </div>

      {policies.loading && <div className="notice">불러오는 중…</div>}
      {policies.error && <div className="notice error">정책을 불러오지 못했습니다. {policies.error}</div>}
      {deleteError && <div className="notice error">삭제하지 못했습니다. {deleteError}</div>}
      {policies.data && policies.data.count === 0 && (
        <div className="notice">정책이 없습니다. "새 정책"으로 만들어 보세요.</div>
      )}

      {policies.data && policies.data.count > 0 && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>이름</th>
                <th>대상 패치(최소 위험도)</th>
                <th>실행 시각</th>
                <th>사용</th>
                <th>배포 단계</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {policies.data.results.map((policy) => (
                <tr key={policy.id}>
                  <td>
                    <Link to={`/policies/${policy.id}/edit`}>{policy.name}</Link>
                  </td>
                  <td>
                    <SeverityBadge severity={policy.min_severity} /> 이상
                  </td>
                  <td className="nowrap">{policy.start_time ? policy.start_time.slice(0, 5) : '지정 안 함'}</td>
                  <td>{policy.is_active ? '사용' : '꺼 둠'}</td>
                  <td>
                    {policy.stages.length === 0
                      ? '단계 없음'
                      : `${policy.stages.map((stage) => groupName.get(stage.group) ?? `그룹 ${stage.group}`).join(' → ')} (${policy.stages.length}단계)`}
                  </td>
                  <td className="actions">
                    <Link to={`/policies/${policy.id}/edit`}>편집</Link>
                    <button className="link" onClick={() => remove(policy)}>
                      삭제
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="axis-note">배포를 시작하고 진행 상태를 보는 기능은 아직 연결되지 않았습니다. 지금은 정책을 만들고 고치는 것만 됩니다.</p>
    </main>
  )
}
