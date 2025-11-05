# Media Static Hosting

`media-static` サービスは、`nginx:alpine` イメージを利用したシンプルな静的ファイルサーバです。`MEDIA_ROOT_HOST_PATH` で指定したディレクトリを `/usr/share/nginx/html` にマウントし、リバースプロキシ (`nginx-proxy`) 経由で公開します。

## 環境変数

`.env` で以下を設定してください。

```env
MEDIA_VIRTUAL_HOST=media.example.space
MEDIA_LETSENCRYPT_EMAIL=admin@example.space
MEDIA_ROOT_HOST_PATH=/home/rocky/srv/makoto-media
```

ローカル動作の場合は `MEDIA_ROOT_HOST_PATH=./media-static` のままでも問題ありません。コンテナ起動後に `docker compose -f base-services/docker-compose.yml up -d` などで有効になります。

## 公開 URL 例

上述の設定の場合、`https://media.example.space/foo/bar.png` でファイルへアクセスできます。`rsync` などを使って対象ディレクトリにファイルを同期させてください。
