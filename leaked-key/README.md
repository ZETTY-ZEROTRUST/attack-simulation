# leaked-key/

쿠팡 사고 재현 시뮬에 사용할 **유출 가정 ES256(ECC NIST P-256) 개인키** 자리.

이 폴더에는 다음 두 파일이 들어가야 한다. (Git에는 절대 커밋 금지)

```
zeti_priv.pem   # PEM 형식 — token_forge.py가 load
zeti_priv.der   # DER 형식 — KMS BYOK import용
```

## 1. 생성 방법 (로컬 시뮬 전용)

```bash
# OpenSSL로 P-256 개인키 생성 (PEM)
openssl ecparam -name prime256v1 -genkey -noout -out zeti_priv.pem

# PEM → DER 변환 (KMS BYOK import용)
openssl ec -in zeti_priv.pem -outform DER -out zeti_priv.der
```

생성 후 `.env`의 `LEAKED_KEY_PATH`가 `zeti_priv.pem`을 가리키는지 확인.

## 2. KMS 연동

- 본 키는 **시뮬 환경 전용**. 운영 KMS 키와 동일 alias(`alias/jwt-signing-key-external`)로
  BYOK 등록하여, 위조 토큰이 운영 검증 경로에서 유효하게 보이게 한다.
- 실 운영 키와 절대 혼용 금지.

## 3. 보안 처리

- `.gitignore`에 `leaked-key/*.pem`, `leaked-key/*.der` 명시.
- 시뮬 종료 후 키 폐기: `shred -u zeti_priv.pem zeti_priv.der` (Linux/Mac) 또는
  Windows에서는 `sdelete` 등 보안 삭제 도구 사용.
- 외부 네트워크/공용 저장소에 절대 업로드하지 않는다.
