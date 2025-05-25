# mcp-ssh-server

**MCP SSH Command Server - プロファイル対応版 v2.0.0**

プロファイル管理によりLLMから機密情報を隠蔽し、セキュアなSSH接続を実現する、Anthropic社のModel Context Protocol (MCP)対応SSHコマンド実行サーバー。
sudo問題修正機能とセッション復旧機能を含む強化版。

## 🎯 主要な特徴

### 🔐 セキュリティ強化
- **機密情報の完全隠蔽**: LLMからホスト名、パスワード、認証情報を隠蔽
- **プロファイル管理**: 事前設定済みのプロファイル名のみでサーバー接続
- **セキュアな認証**: パスワード/秘密鍵認証の柔軟な対応

### ⚡ sudo問題の完全解決
- **パスワード待ちハング**: 完全に解決済み
- **自動修正機能**: sudoコマンドを安全な形に自動変換
- **NOPASSWD対応**: 環境に関係なく安定動作

### 🔄 セッション復旧機能
- **自動復旧**: 30秒超過時の自動セッション復旧
- **強制再接続**: 復旧失敗時の自動再接続
- **長時間処理対応**: バッチ処理等の安定実行

### 🌏 完全な日本語対応
- **文字エンコーディング**: UTF-8完全サポート
- **特殊文字処理**: 感嘆符等の適切な処理
- **ログとエラー**: 日本語メッセージ対応

### 📊 MCP準拠
- **Protocol Version**: 2024-11-05完全準拠
- **JSON-RPC 2.0**: 仕様準拠の通信
- **ツール**: 包括的なSSH操作ツール群
- **リソース**: プロファイル情報とベストプラクティス

## 📋 システム要件

- **Python**: 3.8以上
- **OS**: Windows/Linux/macOS
- **MCP Host**: Claude Desktop、その他のMCP対応クライアント

## 🚀 インストールとセットアップ

### 1. リポジトリのクローン
```bash
git clone https://github.com/your-org/mcp-ssh-server.git
cd mcp-ssh-server
```

### 2. 仮想環境の作成と有効化
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 3. 依存関係のインストール
```bash
pip install -r requirements.txt
```

### 4. SSH プロファイル設定
`src/ssh_profiles.json` を編集して、接続先サーバーの情報を設定：

```json
{
  "profiles": {
    "production-web": {
      "hostname": "prod-web.company.com",
      "username": "webadmin",
      "password": "your_password",
      "port": 22,
      "sudo_password": "your_sudo_password",
      "private_key_path": null,
      "description": "本番Webサーバー",
      "auto_sudo_fix": true,
      "session_recovery": true,
      "default_timeout": 600.0
    },
    "development": {
      "hostname": "192.168.1.100",
      "username": "devuser",
      "password": null,
      "port": 2222,
      "sudo_password": "dev_sudo_pass",
      "private_key_path": "/path/to/dev_key.pem",
      "description": "開発環境",
      "auto_sudo_fix": true,
      "session_recovery": true,
      "default_timeout": 300.0
    }
  },
  "default_profile": "development",
  "profile_metadata": {
    "version": "1.0",
    "last_updated": "2025-01-25T10:00:00Z",
    "created_by": "admin"
  }
}
```

### 5. MCP設定の追加
Claude Desktop等のMCP設定に以下を追加：

```json
{
  "mcpServers": {
    "ssh-command-server": {
      "command": "/path/to/mcp-ssh-server/venv/Scripts/python.exe",
      "args": [
        "/path/to/mcp-ssh-server/src/mcp_ssh_server_profile.py",
        "--debug",
        "--log-file",
        "/path/to/mcp-ssh-server/log/ssh-command-server-debug_log.txt"
      ],
      "env": {
        "PYTHONUTF8": "1",
        "PYTHONPATH": "/path/to/mcp-ssh-server",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

## 🔧 利用可能なツール

### 📡 接続管理
- **`ssh_connect_profile`**: プロファイルを使用したセキュアな接続確立
- **`ssh_list_profiles`**: 利用可能なプロファイル一覧表示
- **`ssh_profile_info`**: プロファイル詳細情報取得
- **`ssh_disconnect`**: SSH接続の切断
- **`ssh_list_connections`**: 現在の接続状況確認

### ⚡ コマンド実行
- **`ssh_execute`**: 単一コマンドの実行（sudo自動修正付き）
- **`ssh_execute_batch`**: 複数コマンドの一括実行
- **`ssh_analyze_command`**: コマンドのsudo使用状況分析

### 🔧 診断・復旧
- **`ssh_test_sudo`**: sudo設定のテスト
- **`ssh_recover_session`**: セッション復旧の手動実行

### 📚 情報リソース
- **`ssh://best-practices/full`**: 完全版ベストプラクティスガイド
- **`ssh://best-practices/profile-usage`**: プロファイル使用方法
- **`ssh://connections`**: 現在の接続状況
- **`ssh://profiles`**: プロファイル一覧

## 💡 基本的な使用方法

### 1. プロファイル一覧の確認
```
ssh_list_profiles()
```

### 2. セキュアな接続確立
```
ssh_connect_profile(
    connection_id="prod1",
    profile_name="production-web"
)
```

### 3. コマンド実行（sudo自動修正）
```
ssh_execute(
    connection_id="prod1",
    command="sudo systemctl status nginx"
)
```

### 4. 複数コマンドの一括実行
```
ssh_execute_batch(
    connection_id="prod1",
    commands=[
        "uptime",
        "sudo ps aux | grep nginx",
        "df -h"
    ]
)
```

## 🔐 セキュリティ機能

### プロファイル管理によるセキュリティ
- **機密情報の隠蔽**: ホスト名、パスワード、認証情報をLLMから完全隠蔽
- **プロファイル識別**: 安全な識別子のみでサーバー接続
- **設定ファイル保護**: 適切な権限設定（600推奨）

### sudo問題の自動解決
- **パスワード待ちハング**: 完全に解決済み
- **自動修正**: `sudo` → `echo 'password' | sudo -S`
- **NOPASSWD対応**: `sudo` → `sudo -n`
- **設定確認**: `ssh_test_sudo` でテスト可能

### セッション復旧
- **自動復旧**: 30秒超過時の自動実行
- **割り込み信号**: Ctrl+C等による復旧
- **強制再接続**: 復旧失敗時の自動再接続

## 📊 パフォーマンス基準

- **プロファイル読み込み**: 0.1秒未満
- **通常コマンド**: 1.0-1.1秒
- **sudoコマンド**: 1.0-1.2秒（自動修正含む）
- **複雑パイプ**: 1.0-1.3秒
- **セッション復旧**: 1-3秒

## 🚨 トラブルシューティング

### よくある問題

#### 1. プロファイル接続失敗
```bash
# プロファイル設定確認
ssh_profile_info("profile_name")

# 接続テスト
ssh_test_sudo("connection_id")
```

#### 2. sudo権限エラー
```bash
# sudo設定テスト
ssh_test_sudo("connection_id")

# 手動セッション復旧
ssh_recover_session("connection_id")
```

#### 3. 特殊文字エラー
```bash
# シングルクォート使用
echo 'Special chars: !@#$%^&*()'

# 日本語は問題なし
echo "こんにちは世界"
```

### ログの確認
```bash
# デバッグログの確認
tail -f log/ssh-command-server-debug_log.txt

# エラーレベルのみ
grep ERROR log/ssh-command-server-debug_log.txt
```

## 🔄 従来方式からの移行

### 旧方式（非推奨）
```
ssh_connect(
    connection_id="server1",
    hostname="192.168.1.100",  # 機密情報露出
    username="user",
    password="password",
    sudo_password="sudo_pass"
)
```

### 新方式（推奨）
```
ssh_connect_profile(
    connection_id="server1",
    profile_name="development-server"  # 安全な識別子のみ
)
```

## 📚 詳細ドキュメント

- **[ベストプラクティス](src/best_practice.md)**: 包括的な使用ガイド
- **[プロファイル設定](src/ssh_profiles.json)**: 設定ファイルの例
- **MCP リソース**: `ssh://best-practices/*` で各種ガイドを参照

## 🤝 貢献

プルリクエストやイシューの報告を歓迎します。

## 📄 ライセンス

MIT License

## 📞 サポート

- **Issues**: GitHub Issues で問題報告
- **Discussions**: 使用方法の質問や議論
- **Documentation**: `src/best_practice.md` で詳細情報

## 🔖 バージョン履歴

### v2.0.0 (Current)
- プロファイル管理による機密情報隠蔽
- sudo問題の完全解決
- セッション復旧機能
- 日本語完全対応
- MCP 2024-11-05準拠

### v1.x.x
- 基本的なSSH接続機能
- 従来方式のコマンド実行

---

## 🎯 LLM向けヒント

このサーバーはLLMからの使用に最適化されています：

1. **セキュア**: プロファイル名のみで接続、機密情報不要
2. **自動修正**: sudoコマンドをそのまま実行可能
3. **復旧機能**: セッション問題は自動解決
4. **日本語対応**: エンコーディング問題なし
5. **包括ツール**: SSH操作に必要な全機能を提供

詳細な使用方法は `ssh://best-practices/full` リソースを参照してください。
