## デプロイ構成メモ

- サーバー上ではリポジトリを `~/infra` に配置する。
- GitHub Actions（`.github/workflows/deploy.yml`）は上記ディレクトリで `docker compose` を実行するよう更新済み。
- `docker-compose.yml` では `GHCR_USER` など `.env` の値を参照するため、サーバー側の `.env` も最新の内容（例: `GHCR_USER=sngm3741`）へ更新しておく。
- Nginx や systemd のパス指定がある場合は `~/infra` に合わせて書き換える。
