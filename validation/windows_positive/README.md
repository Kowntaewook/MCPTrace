# 실제 Windows MCP 통신 → RAM → 원문 대조

이 하네스는 Windows VM에서 공식 Python SDK `mcp==1.26.0`으로 stdio 클라이언트/서버를
실행하고, 실제 요청·응답을 주고받은 상태에서 WinPmem으로 물리 RAM을 수집합니다.
합성 바이트를 덤프에 주입하지 않습니다. GitHub Actions에서는 Windows Server 2022를 사용하며
Windows 11 또는 다른 SDK/클라이언트의 성능을 대신 검증하지 않습니다.

## 실험 조건

동시에 두 개의 독립된 클라이언트/서버 쌍을 실행합니다. 각 쌍은 initialize, initialized 알림,
tools/list와 echo_marker 도구 호출 8회를 수행합니다. 각 도구의 실제 응답에 서버 PID와 입력값을
돌려받아 통신이 수행됐는지 확인합니다. 쌍마다 요청·응답·알림을 합해 21개 메시지를 기록합니다.

- `natural`: SDK 전송/수신 경계에서 정답 로그를 쓰되 직렬화 프레임을 별도 목록에 보관하지 않습니다.
  로깅 자체가 메모리에 영향을 주므로 계측되지 않은 일반 클라이언트와 같다고 보장하지 않습니다.
- `retained`: 같은 실제 통신을 수행하고 직렬화 프레임을 목록에 보관하는 유리한 양성 대조군입니다.
  실제로 보내지 않은 MCP 형태의 JSON 하나도 별도로 보관해 통신 증거와 문자열 흔적을 구분합니다.

수신 로그는 SDK가 파싱한 메시지를 재직렬화한 것이므로 네트워크/파이프 원본 바이트 캡처가 아닙니다.
정답 비교는 객체의 키 순서·공백을 정규화한 논리 메시지 기준이며, 복구 원문 바이트·해시는
별도로 동일한 프로세스 가상 주소에서 재읽어 대조합니다. 메모리 복사본 수로 복원율을 부풀리지 않습니다.

각 조건의 메시지 수, 일치 메시지 수, 원문 보관 여부, 도구 요청·응답 쌍, 전송하지 않은 대조군,
미분류 후보, 동일 PID 내 연결 오류를 따로 출력합니다. 이 작은 통제 실험의 수치를 일반적인
정밀도·재현율 또는 세션 복원 성공률로 해석하지 않습니다. 지연·부하 변화 실험도 별도입니다.

## 실행

별도 Windows 테스트 VM의 관리자 터미널에서 저장소 루트 기준으로 실행합니다.
`workdir`와 `reportdir`는 아직 없는 디렉터리를 지정해야 합니다.

```powershell
python -m pip install -e . -r validation/windows_positive/requirements.txt
python validation/windows_positive/run.py --workdir C:\MCPTraceTest\work --reportdir C:\MCPTraceTest\report
```

WinPmem은 제작자가 제공한 서명된 실행 파일을 사용하고 SHA-256을 확인합니다. 드라이버 로드가
차단되면 실패를 기록하며 보안 설정·드라이버 서명 정책을 변경하지 않습니다. 메모리 수집 후 대상
프로세스를 종료하고, Volatility Windows 심볼 준비 → 플러그인 실행 → 독립 재읽기 → 정답 대조를
수행합니다. 실패를 성공/건너뛰기로 처리하지 않습니다.

GitHub Actions의 `Windows positive memory validation` 워크플로도 같은 하네스를 실행합니다.
기본 브랜치에 반영한 뒤 Actions 화면에서 workflow_dispatch로 수동 실행할 수 있습니다.
실제 덤프는 일회용 VM 안에서만 분석하고 종료 시 삭제합니다. 전체 RAM이나 미분류 후보 원문은
업로드하지 않으며 정답 메시지·대조군과 일치한 아티팩트, 측정값, 수집/분석 로그만 7일 보관합니다.

## 결과 파일

- `manifest.json`: 성공/실패 단계, OS·SDK·플러그인 버전, 커밋, 도구/이미지 해시와 수집 시각.
- `comparison.json`: 조건별 논리 메시지 대조, 중복 포함 아티팩트 수, 연결 평가, 원문 재읽기 수.
- `scan-summaries.json`: 대상 PID별 검사 범위·누락·제한·오류.
- `natural/`, `retained/`: 해당 실행의 정답 로그와 PID/원문 보관 조건.
- `known-test-artifacts.jsonl`: 정답 또는 명시한 비전송 대조군과 일치한 복구 결과만 포함.

성공 조건은 실제 통신한 도구 요청·응답 한 쌍 이상이 동일 PID에서 복구되고, 내보낸 원문이
재읽기 대조를 통과하며, 정답과 대조할 수 있는 연결에 오류가 없는 것입니다. `retained`만 성공해도
전체 실험은 실행 가능성을 확인한 것으로 기록되므로 **반드시 natural/retained 수치를 나눠 읽어야 합니다.**
실제로 수행한 Windows Server 2022 캡처와 조건별 수치는
[양성 검증 보고서](../../docs/windows-positive-memory-validation.md)에 기록했습니다.
