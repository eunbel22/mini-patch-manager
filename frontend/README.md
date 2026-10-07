# frontend

mini-patch-manager의 관리자 화면. React + TypeScript + Vite.

## 실행

백엔드(Django, 8000번 포트)를 먼저 켠 뒤 실행한다.

```
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

브라우저에서 http://127.0.0.1:5173 을 연다. `/api` 요청은 개발 서버가 Django(http://127.0.0.1:8000)로 넘겨 주므로 CORS 설정이 필요 없다.

윈도우에서는 `localhost` 대신 `127.0.0.1`을 쓴다. `localhost`는 먼저 IPv6로 시도하다 거절당해 요청마다 약 2초가 걸린다.

## 명령

| 명령 | 하는 일 |
| --- | --- |
| `npm run dev` | 개발 서버 |
| `npm run build` | 타입 검사 후 배포용 파일 만들기 (`dist/`) |
| `npm run lint` | 코드 검사 |

## 화면

| 주소 | 화면 | 상태 |
| --- | --- | --- |
| `/` | 대시보드 | 완료 |
| `/search` | CVE · KB 검색 | 완료 |
| `/endpoints` | PC 목록 (호스트 이름 검색, 그룹 · 패치 상태 필터, 50개씩 쪽 넘기기) | 완료 |
| `/endpoints/:id` | PC 상세 (취약점 판단, 패치 상태, 설치된 소프트웨어) | 완료 |
| `/policies` | 정책 목록 (이름, 최소 위험도, 실행 시각, 사용, 배포 단계, 편집 · 삭제) | 완료 |
| `/policies/new`, `/policies/:id/edit` | 정책 만들기 · 편집 (배포 단계 목록을 한 화면에서 입력) | 완료 |

## 구조

- `src/api.ts`: 서버 응답 타입과 요청 함수(`useApi`)
- `src/labels.ts`: 위험도 · 패치 상태의 한글 이름과 표시 규칙
- `src/components/`: 공통 부품(툴팁, 위험도 배지)
- `src/pages/`: 화면
- `src/styles.css`: 색 토큰(밝은 · 어두운 모드)과 모양
