## Base Services

Docker Compose で共通インフラをまとめたリポジトリです。現在は以下のサービスを提供しています。

- `messenger-gateway` / `messenger-line-*`: LINE Messaging API 向けのゲートウェイ・Webhook・ワーカー
- `auth-line`: LINE Login (OAuth) を担当する認証サービス。Makoto Club など複数プロダクトから共通利用できるよう想定しています
- `reverse-proxy`: `nginxproxy/nginx-proxy` + `acme-companion` でワイルドカード運用
- `nats`: メッセージングの中心となる NATS サーバー

### ディレクトリ

```
auth-service/
  auth-line/        # LINE Login 認証サービス (Go)
messenger-service/
  messenger-gateway # 外部→NATS のゲートウェイ
  messenger-line/   # LINE Bot 用 Webhook / Worker
reverse-proxy/      # nginx-proxy stack
docker-compose.yml  # 本番用 compose
```

## LINE 認証サービス (`auth-line`)

`auth-line` は LINE Login の認可コードフローをラップし、フロントエンドにアプリ内 JWT を返します。

- `POST /line/login`  
  クロスオリジン `fetch` に対応。リクエスト JSON（`{ origin }`）から `state` を生成し、LINE の認可 URL を応答します。
- `GET /line/callback`  
  LINE からのコールバック。トークン交換→プロフィール取得→JWT 生成まで行い、ポップアップ経由で `window.postMessage` を使ってフロントに戻します。
- `GET /healthz`  
  ヘルスチェック用。

### 環境変数（`.env`）

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `AUTH_LINE_CHANNEL_ID` | `change-me-channel-id` | LINE Login チャネル ID |
| `AUTH_LINE_CHANNEL_SECRET` | `change-me-channel-secret` | チャネルシークレット |
| `AUTH_LINE_REDIRECT_URI` | `https://auth.example.com/line/callback` | LINE デベロッパーに登録するコールバック URL |
| `AUTH_LINE_STATE_SECRET` | `change-me-state-secret` | `state` 署名用シークレット（HMAC-SHA256） |
| `AUTH_LINE_ALLOWED_ORIGINS` | `http://localhost:3000,https://app.example.com` | `POST /line/login` を許可するオリジン |
| `AUTH_LINE_JWT_SECRET` | `change-me-jwt-secret` | アプリ用 JWT 署名キー |
| `AUTH_LINE_JWT_ISSUER` / `AUTH_LINE_JWT_AUDIENCE` | `makoto-club-auth` / `makoto-club-api` | JWT の `iss` / `aud` |
| `AUTH_LINE_JWT_EXPIRES_IN` | `24h` | アプリ JWT の有効期限 |
| `AUTH_LINE_SCOPES` | `profile,openid` | LINE に要求するスコープ |
| `AUTH_LINE_VIRTUAL_HOST` | `auth.iqx9l9hxmw0dj3kt.space` | `nginx-proxy` 用の公開ホスト名 |

- CORS 用に `AUTH_LINE_ALLOWED_ORIGINS` を設定しておくと、フロントからの `fetch` が成功します。
- JWT は HS256 固定です。刷新したい場合は `issueAppToken` を差し替えてください。

## デプロイフロー

GitHub Actions (`.github/workflows/deploy.yml`) は以下を自動化します。

1. `messenger-gateway` / `messenger-line-webhook` / `messenger-line-worker` / `auth-line` の Docker イメージを GHCR へビルド＆プッシュ。
2. Sakura VPS へ SSH し、`~/infra` リポジトリを `main` に同期。
3. `docker compose pull` → `docker compose up -d` で各サービスを再起動。

必要な Secrets は `GHCR_USER`, `GHCR_TOKEN`, `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` です。

## ローカル開発メモ

- `docker compose up -d` で全サービスを立ち上げると、`project01-edge` ネットワーク経由で `nginx-proxy` が自動ルーティングします。ローカルで証明書が不要なら `LETSENCRYPT_*` を空にし、`reverse-proxy` を外して使うことも可能です。
- `auth-line` 単体で動かすときは `go run ./...`（または `make` で追加）で起動できます。ポートは `.env` の `AUTH_LINE_HTTP_ADDR` で変更可能。
- LINE Login の `redirect_uri` は本番と同じホスト名で登録する必要があります。ローカル検証時は ngrok 等で外部公開するか、本番エンドポイントを利用してください。
