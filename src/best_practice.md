# SSH Command Server 使用ガイド - MCP-Host/LLM向けベストプラクティス

## 🎯 概要

ssh-command-serverの包括テスト結果に基づき、MCP-HostやClient側のLLMが効率的かつ安全にサーバーを活用するためのガイドラインです。

## ✅ 主要な改善点の確認

### 解決済みの問題
- **sudoパスワード待ちハング問題**: 完全に解決済み
- **セッション固化**: 自動復旧機能により解決
- **タイムアウト処理**: 適切に実装済み

## 🚀 基本的な使用方針

### 1. 接続確立時のベストプラクティス

```javascript
// 推奨設定
const connectionConfig = {
  connection_id: "unique_identifier",
  hostname: "target_host",
  username: "username",
  password: "password",
  sudo_password: "sudo_password", // 必ず設定
  auto_sudo_fix: true,            // 必ず有効化
  session_recovery: true          // 必ず有効化
};
```

**重要ポイント:**
- `auto_sudo_fix`と`session_recovery`は必ず`true`に設定
- `sudo_password`は事前に設定（NOPASSWD設定があっても問題なし）
- `connection_id`は一意な識別子を使用

### 2. sudoコマンドの適切な使用

#### ✅ 推奨アプローチ
```bash
# LLMはsudoを直接使用可能 - 自動修正が動作
sudo systemctl status ssh
sudo cat /etc/passwd
sudo find /root -name "*.conf"
```

#### ❌ 避けるべき古いアプローチ
```bash
# これらの回避策は不要
echo "password" | sudo -S command
sudo -n command  # NOPASSWDチェック
```

**理由**: 自動修正機能により、LLMは通常のsudoコマンドをそのまま使用可能

### 3. エラーハンドリング戦略

#### パフォーマンス基準値
- **通常コマンド**: 1.0-1.1秒
- **sudoコマンド**: 1.0-1.2秒
- **複雑パイプ**: 1.0-1.3秒

#### エラー判定基準
```javascript
// レスポンス評価基準
if (response.execution_time > 30.0) {
  // タイムアウトまたは問題あり
  await ssh_recover_session(connection_id);
}

if (response.status === "recovered") {
  // セッション復旧が発生 - 正常に継続可能
  console.log("Session recovered, continuing...");
}

if (response.exit_code !== 0 && response.exit_code !== null) {
  // コマンドエラー（sudo問題ではない）
  handleCommandError(response);
}
```

## 🛡️ セキュリティとベストプラクティス

### 1. コマンド実行時の注意事項

#### 特殊文字の扱い
```bash
# ✅ 安全な特殊文字使用
echo 'Special chars: !@#$%^&*()'  # シングルクォート推奨
echo "Normal text with spaces"    # 通常文字はダブルクォートOK

# ⚠️ 注意が必要
echo "History expansion: !!"      # ダブルクォート内の感嘆符
```

#### 日本語文字の使用
```bash
# ✅ 完全サポート
echo "こんにちは世界"
sudo echo "日本語のsudoテスト"
echo "日本語検索" | grep "検索"
```

### 2. パフォーマンス最適化

#### バッチ実行の活用
```javascript
// 関連コマンドはバッチで実行
const commands = [
  "ls -la /var/log",
  "du -sh /var/log/*",
  "tail -10 /var/log/syslog"
];

await ssh_execute_batch(connection_id, commands, {
  stop_on_error: false  // 継続実行推奨
});
```

#### 適切なタイムアウト設定
```javascript
// コマンドタイプ別タイムアウト
const timeouts = {
  simple: 10,    // echo, pwd, whoami
  search: 30,    // find, grep
  system: 60,    // systemctl, package operations
  heavy: 300     // バックアップ、大量データ処理
};
```

## 🔧 高度な使用テクニック

### 1. 複雑なパイプチェーンの構築

```bash
# ✅ 推奨 - 複雑な処理も単一コマンドで
sudo find /etc -name "*.conf" | head -20 | xargs sudo ls -la | grep "$(date +%Y)"

# ✅ 作業ディレクトリ指定
ls -la | grep "\.txt$"  # working_directory: "/tmp"指定
```

### 2. エラー処理を含む堅牢なコマンド

```bash
# ✅ エラーハンドリング込みのコマンド
sudo systemctl status nginx 2>/dev/null || echo "Nginx not found"
test -f /etc/nginx/nginx.conf && sudo cat /etc/nginx/nginx.conf || echo "Config not found"
```

### 3. セッション管理の活用

```javascript
// セッション状態の定期チェック
async function healthCheck(connection_id) {
  const connections = await ssh_list_connections();
  const conn = connections.connections[connection_id];
  
  if (!conn || !conn.is_alive) {
    await ssh_recover_session(connection_id);
  }
}

// 長時間処理前のセッション準備
await ssh_execute(connection_id, "echo 'Session check'");
```

## ⚡ LLM向け実装パターン

### 1. コマンド生成時の判断フロー

```javascript
function generateCommand(intent, params) {
  let command = baseCommand;
  
  // sudoが必要かの判断
  if (requiresPrivileges(intent)) {
    command = `sudo ${command}`;
    // 自動修正により、パスワード処理は不要
  }
  
  // 特殊文字がある場合の対策
  if (hasSpecialChars(params)) {
    command = command.replace(/"/g, '\\"');  // エスケープ
    // または
    command = `'${command}'`;  // シングルクォートで囲む
  }
  
  return command;
}
```

### 2. 結果の解釈パターン

```javascript
function interpretResponse(response) {
  // 成功パターン
  if (response.success && response.exit_code === 0) {
    return {
      status: 'success',
      data: response.stdout,
      message: 'Command executed successfully'
    };
  }
  
  // 復旧パターン（正常動作）
  if (response.status === 'recovered') {
    return {
      status: 'success',
      data: response.stdout,
      message: 'Command executed after session recovery'
    };
  }
  
  // sudo自動修正パターン（正常動作）
  if (response.auto_fixed && response.sudo_fix_applied) {
    return {
      status: 'success',
      data: response.stdout,
      message: 'Command executed with sudo auto-fix'
    };
  }
  
  // エラーパターン
  return {
    status: 'error',
    error: response.stderr || 'Command failed',
    exit_code: response.exit_code
  };
}
```

### 3. 対話的なコマンド構築

```javascript
async function buildComplexOperation(steps) {
  const results = [];
  
  for (const step of steps) {
    try {
      const result = await ssh_execute(connection_id, step.command);
      results.push(result);
      
      // 前のステップの結果を次のステップで活用
      if (step.useResult) {
        step.next.command = step.next.command.replace(
          '{{RESULT}}', 
          result.stdout.trim()
        );
      }
      
    } catch (error) {
      // エラー時の復旧処理
      await ssh_recover_session(connection_id);
      throw error;
    }
  }
  
  return results;
}
```

## 🚨 トラブルシューティング

### 1. よくある問題と対策

#### 問題: コマンドが応答しない
```javascript
// 対策: セッション復旧
await ssh_recover_session(connection_id);
await ssh_execute(connection_id, "echo 'test'");  // 復旧確認
```

#### 問題: 特殊文字でエラー
```javascript
// 対策: クォート方法の変更
const command = params.includes('!') 
  ? `'${originalCommand}'`    // シングルクォート
  : `"${originalCommand}"`;   // ダブルクォート
```

#### 問題: sudo権限エラー
```javascript
// 確認: sudo設定のテスト
const sudoTest = await ssh_test_sudo(connection_id);
if (!sudoTest.success) {
  // sudo設定に問題がある場合の対処
}
```

### 2. デバッグとモニタリング

```javascript
// レスポンス詳細の記録
function logResponse(response) {
  console.log({
    command: response.command,
    execution_time: response.execution_time,
    auto_fixed: response.auto_fixed,
    session_recovered: response.session_recovered,
    exit_code: response.exit_code
  });
}

// パフォーマンスアラート
if (response.execution_time > 10.0) {
  console.warn(`Slow command detected: ${response.command}`);
}
```

## 📊 パフォーマンス最適化指針

### 1. 効率的なコマンド設計

#### 推奨パターン
```bash
# ✅ 単一コマンドで複数処理
ps aux | grep nginx | awk '{print $2}' | head -5

# ✅ 作業ディレクトリ活用
# working_directory: "/var/log" として
tail -100 *.log | grep ERROR
```

#### 非推奨パターン
```bash
# ❌ 複数回の往復
ssh_execute("cd /var/log");     # 効果なし
ssh_execute("ls");              # 元のディレクトリに戻っている
ssh_execute("pwd");             # /home/user
```

### 2. バッチ実行の活用場面

```javascript
// ✅ 関連操作をまとめる
const systemCheck = [
  "uptime",
  "free -h", 
  "df -h",
  "ps aux | head -10"
];

// ✅ エラー継続で完全な情報収集
await ssh_execute_batch(connection_id, systemCheck, {
  stop_on_error: false
});
```

## 🎓 まとめ

### LLMが覚えておくべき重要ポイント

1. **sudoは直接使用可能** - 自動修正により従来の回避策は不要
2. **セッション復旧は自動** - `status: "recovered"`は正常動作
3. **特殊文字はシングルクォート** - 感嘆符対策
4. **日本語は完全サポート** - エンコーディング問題なし
5. **パフォーマンスは安定** - 1秒前後が基準値
6. **エラーハンドリング不要** - サーバー側で適切に処理

### 導入効果

- **開発効率向上**: sudo問題の解決により、LLMのコマンド生成が単純化
- **安定性向上**: セッション復旧により長時間動作が可能
- **保守性向上**: 特殊ケース対応が不要

ssh-command-serverの改善により、LLMはより直感的で安全なLinuxシステム操作が可能になりました。
