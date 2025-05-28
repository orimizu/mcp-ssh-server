# Knowledge システム バックアップ計画

## 🎯 バックアップ対象の優先度分類

### 🔴 最優先（データ損失時の影響: 致命的）
- **データベース**: `/home/tomcat/.knowledge/db/` (800KB)
- **暗号化キー**: `/home/tomcat/.knowledge/key.txt` (64B)
- **検索インデックス**: `/home/tomcat/.knowledge/index/` (数KB)

### 🟡 重要（復旧可能だが時間がかかる）
- **アプリケーション**: `/opt/apache-tomcat-8.5.34/webapps/knowledge/` (315MB)
- **設定ファイル**: WEB-INF/classes内の.properties
- **一時ファイル**: `/home/tomcat/.knowledge/tmp/`

### 🟢 参考（必要に応じて）
- **ログファイル**: `/home/tomcat/.knowledge/logs/` (50MB)

## 📦 バックアップ方式の提案

### 方式1: 段階的バックアップ（推奨）
```bash
# 日次: 重要データのみ（約1MB）
/backup/daily/knowledge_data_YYYYMMDD.tar.gz

# 週次: アプリケーション込み（約200MB圧縮後）
/backup/weekly/knowledge_full_YYYYMMDD.tar.gz

# 月次: ログ込み完全バックアップ（約300MB圧縮後）
/backup/monthly/knowledge_complete_YYYYMMDD.tar.gz
```

### 方式2: シンプルバックアップ
```bash
# 毎日同じ内容をバックアップ（約200MB圧縮後）
/backup/knowledge_backup_YYYYMMDD.tar.gz
```

## 🔧 実装提案

### 1. バックアップディレクトリ作成
```bash
mkdir -p /backup/{daily,weekly,monthly}
chown root:root /backup
chmod 750 /backup
```

### 2. バックアップスクリプト作成
```bash
#!/bin/bash
# /root/scripts/knowledge_backup.sh

BACKUP_TYPE=${1:-"daily"}
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/${BACKUP_TYPE}"

case $BACKUP_TYPE in
    "daily")
        # データベース + 重要ファイルのみ
        tar -czf "${BACKUP_DIR}/knowledge_data_${DATE}.tar.gz" \
            --exclude="/home/tomcat/.knowledge/logs" \
            --exclude="/home/tomcat/.knowledge/tmp/*" \
            /home/tomcat/.knowledge/
        ;;
    "weekly")
        # アプリケーション込み
        tar -czf "${BACKUP_DIR}/knowledge_full_${DATE}.tar.gz" \
            --exclude="/home/tomcat/.knowledge/logs" \
            /home/tomcat/.knowledge/ \
            /opt/apache-tomcat-8.5.34/webapps/knowledge/
        ;;
    "monthly")
        # 完全バックアップ
        tar -czf "${BACKUP_DIR}/knowledge_complete_${DATE}.tar.gz" \
            /home/tomcat/.knowledge/ \
            /opt/apache-tomcat-8.5.34/webapps/knowledge/
        ;;
esac

# 古いバックアップの削除
find ${BACKUP_DIR} -name "knowledge_*" -mtime +30 -delete
```

### 3. Cron設定
```bash
# 毎日 02:00 - データバックアップ
0 2 * * * /root/scripts/knowledge_backup.sh daily

# 毎週日曜 03:00 - フルバックアップ
0 3 * * 0 /root/scripts/knowledge_backup.sh weekly

# 毎月1日 04:00 - 完全バックアップ
0 4 1 * * /root/scripts/knowledge_backup.sh monthly
```

## 🔄 復旧手順

### データベース復旧
```bash
# Tomcatサービス停止
service tomcat stop

# データベースファイル復旧
tar -xzf /backup/daily/knowledge_data_YYYYMMDD.tar.gz -C /

# 権限修正
chown -R tomcat:tomcat /home/tomcat/.knowledge/

# Tomcatサービス再開
service tomcat start
```

### 完全復旧
```bash
# 完全バックアップから復旧
tar -xzf /backup/monthly/knowledge_complete_YYYYMMDD.tar.gz -C /
chown -R tomcat:tomcat /home/tomcat/.knowledge/
chown -R tomcat:tomcat /opt/apache-tomcat-8.5.34/webapps/knowledge/
service tomcat restart
```

## 📊 ストレージ使用量予測

| バックアップ種別 | 頻度 | サイズ予測 | 保存期間 | 月間容量 |
|------------------|------|------------|----------|----------|
| 日次データ       | 毎日 | 1MB        | 30日     | 30MB     |
| 週次フル         | 毎週 | 200MB      | 30日     | 800MB    |
| 月次完全         | 毎月 | 300MB      | 365日    | 3.6GB    |
| **合計**         |      |            |          | **4.4GB** |

## ⚠️ 重要な注意点

1. **サービス停止不要**: tar -czfは稼働中でも安全に実行可能
2. **権限管理**: バックアップファイルはroot権限で保護
3. **容量監視**: 月4.4GBの増加（現在47GB空き容量で十分）
4. **テスト**: バックアップからの復旧テストを定期実行
5. **外部保存**: 重要バックアップは別サーバーにも転送推奨

## 🚀 次のステップ

1. バックアップディレクトリとスクリプト作成
2. 初回手動バックアップでテスト実行
3. Cron設定でスケジュール化
4. 復旧テストの実施
5. 外部バックアップの検討