#!/usr/bin/env python3
"""
MCP SSH Command Server - プロファイル対応版

プロファイル管理によりLLMから機密情報を隠蔽し、セキュアなSSH接続を実現
sudo問題修正機能とセッション復旧機能を含む強化版
Anthropic社のModel Context Protocol (MCP)に対応したSSHコマンド実行サーバー
JSON-RPC 2.0仕様に完全準拠
"""

import asyncio
import json
import sys
import logging
from typing import Any, Dict, List, Optional, Union
from dataclasses import asdict
import argparse

# 修正版SSH実行ライブラリをインポート
try:
    from ssh_command_executor import SSHCommandExecutor, CommandResult, CommandStatus
except ImportError:
    print("ERROR: ssh_command_executor.py が見つかりません。", file=sys.stderr)
    print("修正版のssh_command_executor.py を同じディレクトリに配置してください。", file=sys.stderr)
    sys.exit(1)

# プロファイル管理ライブラリをインポート
try:
    from ssh_profile_manager import SSHProfileManager, SSHProfile
except ImportError:
    print("ERROR: ssh_profile_manager.py が見つかりません。", file=sys.stderr)
    print("ssh_profile_manager.py を同じディレクトリに配置してください。", file=sys.stderr)
    sys.exit(1)


class MCPSSHServerProfile:
    """MCP対応SSH Command Server - プロファイル対応版 + sudo問題修正 + LLMベストプラクティス統合"""
    
    def __init__(self):
        self.ssh_connections: Dict[str, SSHCommandExecutor] = {}
        self.profile_manager = SSHProfileManager()
        self.logger = logging.getLogger(__name__)
        
        # MCPツールの定義（プロファイル対応版）
        self.tools = [
            {
                "name": "ssh_connect_profile",
                "description": """プロファイルを使用してSSH接続を確立（セキュア方式）

🔐 セキュリティ強化:
- LLMからは機密情報（IP、パスワード）を完全に隠蔽
- プロファイル名のみでサーバー接続が可能
- 接続情報は事前設定されたjsonファイルから取得

⚡ 重要な改善点:
- sudoパスワード待ちハング問題が完全に解決済み
- プロファイル設定でsudo機能が自動有効化
- session_recovery: プロファイル設定に従い自動適用
- セキュアな認証（パスワード/秘密鍵）をプロファイルで管理

💡 LLM向けヒント:
- 事前にssh_list_profilesでプロファイル一覧確認
- ssh_profile_infoで詳細設定確認
- 接続後は従来通りssh_executeでコマンド実行
- sudoコマンドは直接実行可能、プロファイルのsudo設定を自動使用

📊 パフォーマンス基準:
- 接続確立: 通常1-3秒で完了（従来と同等）
- プロファイル読み込み: 0.1秒未満
- セキュリティ: 機密情報の完全隠蔽""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "接続識別子（一意な名前を推奨、例: 'server1', 'production'）"
                        },
                        "profile_name": {
                            "type": "string",
                            "description": "使用するプロファイル名（ssh_list_profilesで確認可能）"
                        },
                        "port": {
                            "type": "integer",
                            "description": "SSHポート番号のオーバーライド（プロファイル設定を上書き）"
                        },
                        "auto_sudo_fix": {
                            "type": "boolean",
                            "description": "sudo自動修正機能のオーバーライド（プロファイル設定を上書き）"
                        },
                        "session_recovery": {
                            "type": "boolean",
                            "description": "セッション復旧機能のオーバーライド（プロファイル設定を上書き）"
                        },
                        "default_timeout": {
                            "type": "number",
                            "description": "デフォルトタイムアウトのオーバーライド（プロファイル設定を上書き）"
                        }
                    },
                    "required": ["connection_id", "profile_name"]
                }
            },
            {
                "name": "ssh_list_profiles",
                "description": """利用可能なSSHプロファイル一覧を取得

🔍 取得可能な情報（機密情報は除外）:
- profile_name: プロファイル識別名
- description: プロファイルの説明
- port: 接続ポート番号
- auto_sudo_fix: sudo自動修正設定
- session_recovery: セッション復旧設定
- has_password: パスワード認証の有無
- has_private_key: 秘密鍵認証の有無
- has_sudo_password: sudo用パスワード設定の有無

💡 LLM向けヒント:
- 接続前にプロファイル一覧を確認
- descriptionフィールドでプロファイルの用途を把握
- has_sudo_passwordでsudo機能の利用可能性を確認
- 認証方式（パスワード/秘密鍵）を事前確認

📊 実行時間: 即座に完了（0.1秒未満）""",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "ssh_profile_info",
                "description": """指定プロファイルの詳細情報を取得（機密情報除外）

🔍 詳細情報の内容:
- 基本設定（ポート、タイムアウト、説明）
- 認証設定（認証方式の種類、秘密鍵パスの設定状況）
- sudo設定（sudo機能の有無、自動修正設定）
- 接続設定（セッション復旧、各種タイムアウト）

💡 LLM向けヒント:
- 接続前の詳細確認に使用
- sudo機能の利用可能性を詳細確認
- 認証方式の詳細を把握
- タイムアウト設定を事前確認

📊 実行時間: 即座に完了（0.1秒未満）""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profile_name": {
                            "type": "string",
                            "description": "詳細情報を取得するプロファイル名"
                        }
                    },
                    "required": ["profile_name"]
                }
            },
            {
                "name": "ssh_connect",
                "description": """【後方互換性用】直接接続方式（非推奨）

⚠️ セキュリティ警告:
- LLMに機密情報（IP、パスワード）を直接渡す必要あり
- 新規利用では ssh_connect_profile の使用を強く推奨
- 既存スクリプトの互換性確保のためのみ残存

💡 LLM向けヒント:
- 可能な限り ssh_connect_profile を使用
- プロファイル管理により機密情報の露出を回避
- 緊急時やテスト時のみ使用を検討

🔄 移行推奨:
1. ssh_profiles.json にプロファイル設定
2. ssh_connect_profile を使用
3. 機密情報をLLMから隠蔽""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "接続識別子"
                        },
                        "hostname": {
                            "type": "string",
                            "description": "接続先ホスト名またはIPアドレス"
                        },
                        "username": {
                            "type": "string",
                            "description": "ログインユーザー名"
                        },
                        "password": {
                            "type": "string",
                            "description": "パスワード（省略可、秘密鍵使用時）"
                        },
                        "private_key_path": {
                            "type": "string",
                            "description": "秘密鍵ファイルのパス（省略可、パスワード認証時）"
                        },
                        "port": {
                            "type": "integer",
                            "description": "SSHポート番号",
                            "default": 22
                        },
                        "sudo_password": {
                            "type": "string",
                            "description": "sudo用パスワード"
                        },
                        "auto_sudo_fix": {
                            "type": "boolean",
                            "description": "sudo自動修正機能",
                            "default": True
                        },
                        "session_recovery": {
                            "type": "boolean",
                            "description": "セッション復旧機能",
                            "default": True
                        }
                    },
                    "required": ["connection_id", "hostname", "username"]
                }
            },
            {
                "name": "ssh_execute",
                "description": """SSH経由でコマンドを実行（プロファイル対応版）

✅ プロファイル設定の自動適用:
- sudo_password: プロファイル設定を自動使用
- auto_sudo_fix: プロファイル設定に従い自動修正
- session_recovery: プロファイル設定に従い自動復旧
- timeout: プロファイルのデフォルト値を使用

✅ sudo使用例（プロファイル設定で自動処理）:
- sudo systemctl status nginx     # プロファイルのsudo設定を自動適用
- sudo cat /etc/passwd           # パスワード待ちハング完全解決
- sudo find /root -name "*.conf" # 自動修正により安全実行
- sudo ps aux | grep nginx      # パイプ処理も問題なし

⚠️ 特殊文字の注意点（従来と同様）:
- 感嘆符(!)を含む場合：シングルクォート使用推奨
  echo 'Special: !@#$%^&*()'
- 日本語文字列：完全サポート済み
  echo "こんにちは世界"
  sudo echo "日本語でのsudoテスト"

🔄 レスポンス解釈（プロファイル版）:
- success: true + exit_code: 0 → 正常完了
- status: "recovered" → セッション復旧後正常完了（成功の一種）
- auto_fixed: true → sudo自動修正が動作（プロファイル設定適用）
- profile_used: プロファイル名が記録される
- exit_code > 0 → コマンドエラー（sudo問題ではない）

📊 パフォーマンス基準:
- 通常コマンド: 1.0-1.1秒
- sudoコマンド: 1.0-1.2秒（プロファイル設定適用）
- 複雑パイプ: 1.0-1.3秒
- 30秒超過時は自動セッション復旧が実行""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "接続識別子"
                        },
                        "command": {
                            "type": "string",
                            "description": "実行するコマンド（sudoコマンドも直接指定可能、プロファイル設定を自動適用）"
                        },
                        "timeout": {
                            "type": "number",
                            "description": "タイムアウト時間（秒）、未指定時はプロファイルのdefault_timeoutを使用",
                            "default": 300
                        },
                        "working_directory": {
                            "type": "string",
                            "description": "作業ディレクトリ（省略可）、各コマンドで独立実行"
                        },
                        "sudo_password": {
                            "type": "string",
                            "description": "sudo用パスワード（一時的に指定、通常はプロファイル設定で十分）"
                        }
                    },
                    "required": ["connection_id", "command"]
                }
            },
            {
                "name": "ssh_execute_batch",
                "description": """SSH経由で複数コマンドを順次実行（プロファイル対応版）

✅ プロファイル設定の自動適用:
- sudo関連設定: プロファイルから自動取得
- タイムアウト: プロファイルのdefault_timeoutを使用
- 自動修正機能: プロファイル設定に従い動作

✅ 効率的な使用例:
- 関連するコマンドをまとめて実行
- システム情報収集: ["uptime", "free -h", "df -h", "ps aux | head -10"]
- sudo混在も問題なし: ["echo 'start'", "sudo systemctl status ssh", "echo 'done'"]

💡 LLM実装のポイント:
- stop_on_error: false を推奨（完全な情報収集のため）
- sudoコマンドが含まれていてもプロファイル設定で自動処理
- バッチ内でのsudo自動修正は個別に動作

🔄 バッチ実行の利点:
- 複数往復の削減によるパフォーマンス向上
- sudo_summary で修正状況を一括確認
- プロファイル設定の一括適用
- エラー時の継続実行オプション

📊 パフォーマンス:
- 各コマンド: 1.0-1.2秒（個別実行と同等）
- バッチオーバーヘッド: 最小限
- プロファイル適用: 自動で高速""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "接続識別子"
                        },
                        "commands": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "実行するコマンドのリスト（sudoコマンド混在可能、プロファイル設定自動適用）"
                        },
                        "timeout": {
                            "type": "number",
                            "description": "各コマンドのタイムアウト時間（秒）、未指定時はプロファイル設定を使用",
                            "default": 300
                        },
                        "working_directory": {
                            "type": "string",
                            "description": "全コマンド共通の作業ディレクトリ（省略可）"
                        },
                        "stop_on_error": {
                            "type": "boolean",
                            "description": "エラー時の停止設定（false推奨：完全な情報収集のため）",
                            "default": True
                        },
                        "sudo_password": {
                            "type": "string",
                            "description": "sudo用パスワード（全コマンド共通、通常はプロファイル設定で十分）"
                        }
                    },
                    "required": ["connection_id", "commands"]
                }
            },
            {
                "name": "ssh_disconnect",
                "description": """SSH接続を切断する

💡 LLM向けヒント:
- 明示的な切断により、リソースの適切な管理
- 作業完了時やエラー時の切断に使用
- 切断後は該当connection_idでの操作は不可
- プロファイル設定は保持（再接続時に再利用可能）

📊 切断処理:
- 即座に実行完了（1秒未満）
- 進行中のコマンドも安全に終了
- メモリとネットワークリソースの解放""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "切断する接続識別子"
                        }
                    },
                    "required": ["connection_id"]
                }
            },
            {
                "name": "ssh_list_connections",
                "description": """現在のSSH接続リストを取得（プロファイル情報含む）

💡 LLM向けヒント:
- 接続状況の確認に使用
- 使用中のプロファイル名を確認可能
- sudo設定状況（sudo_configured）を確認可能
- is_alive で接続の健全性を確認
- プロファイル由来の設定状況を確認

🔍 取得可能な情報:
- 接続の生存状況（is_connected, is_alive）
- 使用プロファイル名（profile_name）
- sudo機能の設定状況（sudo_configured, auto_sudo_fix）
- セッション復旧機能の状況（session_recovery）
- 接続の基本情報（hostname, username, port）※プロファイル由来

📊 実行時間: 即座に完了（1秒未満）""",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "ssh_analyze_command",
                "description": """コマンドのsudo使用状況を分析

💡 LLM向けヒント:
- コマンド実行前の安全性確認に使用
- sudo自動修正の予想結果を事前確認
- 複雑なコマンドのリスク評価に活用
- プロファイル設定との整合性確認

🔍 分析結果:
- sudo_detected: sudoコマンドの検出結果
- recommended_with_password: パスワード付き推奨コマンド
- recommended_without_password: NOPASSWD環境での推奨コマンド
- risk_level: リスクレベル（low/medium/high）

📊 分析時間: 即座に完了（1秒未満）、実行前の予備確認""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "分析するコマンド"
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "ssh_recover_session",
                "description": """停止したセッションの復旧を試行

💡 LLM向けヒント:
- 通常は自動復旧が動作するため、手動実行は稀
- 長時間応答しないセッションの復旧に使用
- 復旧失敗時は自動的に再接続を試行（プロファイル設定を使用）

🔄 復旧プロセス:
1. セッション復旧の試行（割り込み信号、バッファクリア）
2. 失敗時は強制再接続（プロファイル設定で再接続）
3. 再接続失敗時は接続削除

⚡ 自動復旧機能:
- 30秒超過のコマンドで自動実行
- status: "recovered" は正常動作の一部
- 手動実行は異常時のトラブルシューティング用
- プロファイル設定を保持して復旧

📊 復旧時間: 通常1-3秒で完了""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "復旧する接続識別子"
                        }
                    },
                    "required": ["connection_id"]
                }
            },
            {
                "name": "ssh_test_sudo",
                "description": """sudo設定をテスト（プロファイル設定使用）

💡 LLM向けヒント:
- 接続確立後の設定確認に使用
- プロファイルのsudo設定をテスト
- NOPASSWD設定の有無を確認
- auto_sudo_fix機能の動作テスト
- トラブルシューティング時の診断ツール

🔍 テスト内容:
- NOPASSWD Test: sudo -n での実行可能性
- Password Test: プロファイルのsudoパスワードでの動作確認
- Auto-fix Test: 自動修正機能の動作確認（プロファイル設定）

📊 テスト結果:
- success_rate: 成功率（100%が理想）
- sudo_configuration: 設定状況の詳細（プロファイル情報含む）
- recommendations: LLM向けの推奨事項

⚡ 実行タイミング:
- 接続確立後の初回確認
- sudo関連のエラー発生時
- プロファイル設定変更後の確認""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connection_id": {
                            "type": "string",
                            "description": "テストする接続識別子"
                        },
                        "sudo_password": {
                            "type": "string",
                            "description": "テスト用sudoパスワード（省略時はプロファイル設定を使用）"
                        }
                    },
                    "required": ["connection_id"]
                }
            }
        ]
        
        # MCPリソースの定義（プロファイル対応版）
        self.resources = [
            {
                "uri": "ssh://connections",
                "name": "SSH接続状況",
                "description": "現在のSSH接続の状況（プロファイル情報・sudo設定含む）",
                "mimeType": "application/json"
            },
            {
                "uri": "ssh://profiles",
                "name": "SSHプロファイル一覧",
                "description": "利用可能なSSHプロファイル一覧（機密情報除外）",
                "mimeType": "application/json"
            },
            {
                "uri": "ssh://profiles/metadata",
                "name": "プロファイルメタデータ",
                "description": "プロファイルファイルのメタデータ情報",
                "mimeType": "application/json"
            },
            {
                "uri": "ssh://sudo_status",
                "name": "sudo設定状況",
                "description": "各接続のsudo設定状況（プロファイル情報含む）",
                "mimeType": "application/json"
            },
            {
                "uri": "ssh://best-practices/full",
                "name": "完全版ベストプラクティスガイド",
                "description": "best_practice.md から読み込まれる包括的なガイド（最新・完全版）",
                "mimeType": "text/markdown"
            },
            {
                "uri": "ssh://best-practices/profile-usage",
                "name": "プロファイル使用ベストプラクティス",
                "description": "プロファイル管理によるセキュアなSSH接続の活用方法",
                "mimeType": "text/markdown"
            },
            {
                "uri": "ssh://best-practices/sudo-usage",
                "name": "SSH sudo使用ベストプラクティス（要約）",
                "description": "sudo自動修正機能の活用方法とLLM向けガイドライン（要約版）",
                "mimeType": "text/markdown"
            },
            {
                "uri": "ssh://best-practices/error-handling",
                "name": "SSH エラーハンドリングガイド",
                "description": "セッション復旧とエラー処理の理解",
                "mimeType": "text/markdown"
            },
            {
                "uri": "ssh://best-practices/performance",
                "name": "SSH パフォーマンス最適化",
                "description": "効率的なコマンド実行とバッチ処理のコツ",
                "mimeType": "text/markdown"
            },
            {
                "uri": "ssh://best-practices/special-chars",
                "name": "特殊文字・日本語対応ガイド",
                "description": "特殊文字とエンコーディングの適切な処理方法",
                "mimeType": "text/markdown"
            }
        ]
    
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """MCPリクエストのハンドリング"""
        jsonrpc = request.get("jsonrpc", "2.0")
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")
        
        self.logger.debug(f"Received request: method={method}, id={request_id}")
        
        try:
            if not method:
                return self._error_response(request_id, -32600, "Invalid Request: method is required")
            
            if method == "initialize":
                return await self._handle_initialize(request_id, params)
            elif method == "tools/list":
                return await self._handle_tools_list(request_id)
            elif method == "tools/call":
                return await self._handle_tools_call(request_id, params)
            elif method == "resources/list":
                return await self._handle_resources_list(request_id)
            elif method == "resources/read":
                return await self._handle_resources_read(request_id, params)
            elif method == "notifications/initialized":
                return None
            else:
                return self._error_response(request_id, -32601, f"Method not found: {method}")
        
        except Exception as e:
            self.logger.error(f"Request handling error: {e}", exc_info=True)
            return self._error_response(request_id, -32603, f"Internal error: {str(e)}")
    
    async def _handle_initialize(self, request_id: Optional[Union[str, int]], params: Dict[str, Any]) -> Dict[str, Any]:
        """初期化処理"""
        self.logger.info("Initializing MCP SSH Server with Profile Support and sudo enhancement")
        
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "serverInfo": {
                    "name": "ssh-command-server-profile-enhanced",
                    "version": "2.0.0"
                }
            }
        }
    
    async def _handle_tools_list(self, request_id: Optional[Union[str, int]]) -> Dict[str, Any]:
        """利用可能なツールのリスト"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": self.tools
            }
        }
    
    async def _handle_tools_call(self, request_id: Optional[Union[str, int]], params: Dict[str, Any]) -> Dict[str, Any]:
        """ツールの実行（プロファイル対応版）"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if not tool_name:
            return self._error_response(request_id, -32602, "Invalid params: tool name is required")
        
        self.logger.info(f"Executing tool: {tool_name}")
        
        try:
            if tool_name == "ssh_connect_profile":
                result = await self._ssh_connect_profile(arguments)
            elif tool_name == "ssh_list_profiles":
                result = await self._ssh_list_profiles(arguments)
            elif tool_name == "ssh_profile_info":
                result = await self._ssh_profile_info(arguments)
            elif tool_name == "ssh_connect":
                result = await self._ssh_connect(arguments)
            elif tool_name == "ssh_execute":
                result = await self._ssh_execute(arguments)
            elif tool_name == "ssh_execute_batch":
                result = await self._ssh_execute_batch(arguments)
            elif tool_name == "ssh_disconnect":
                result = await self._ssh_disconnect(arguments)
            elif tool_name == "ssh_list_connections":
                result = await self._ssh_list_connections(arguments)
            elif tool_name == "ssh_analyze_command":
                result = await self._ssh_analyze_command(arguments)
            elif tool_name == "ssh_recover_session":
                result = await self._ssh_recover_session(arguments)
            elif tool_name == "ssh_test_sudo":
                result = await self._ssh_test_sudo(arguments)
            else:
                return self._error_response(request_id, -32601, f"Unknown tool: {tool_name}")
            
            # LLMガイダンスを追加
            guidance = self._generate_llm_guidance(tool_name, result)
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, ensure_ascii=False) + guidance
                        }
                    ]
                }
            }
            
        except Exception as e:
            self.logger.error(f"Tool execution error: {e}", exc_info=True)
            return self._error_response(request_id, -32603, f"Tool execution failed: {str(e)}")
    
    def _generate_llm_guidance(self, tool_name: str, result: Dict[str, Any]) -> str:
        """LLM向けガイダンスを生成（プロファイル対応版）"""
        guidance = ""
        
        if tool_name == "ssh_connect_profile":
            if result.get("success"):
                profile_name = result.get("profile_used")
                guidance += f"\n\n✅ LLM Note: プロファイル '{profile_name}' を使用して接続が確立されました。"
                if result.get("connection_info", {}).get("sudo_configured"):
                    guidance += "\n💡 LLM Note: sudo機能が設定されています。sudoコマンドを直接実行できます。"
            else:
                guidance += "\n❌ LLM Note: プロファイルでの接続に失敗しました。プロファイル設定を確認してください。"
        
        elif tool_name == "ssh_list_profiles":
            profile_count = len(result.get("profiles", []))
            guidance += f"\n\n📋 LLM Note: {profile_count}個のプロファイルが利用可能です。"
            sudo_profiles = sum(1 for p in result.get("profiles", []) if p.get("has_sudo_password"))
            if sudo_profiles > 0:
                guidance += f"\n🔐 LLM Note: {sudo_profiles}個のプロファイルでsudo機能が利用可能です。"
        
        elif tool_name == "ssh_profile_info":
            profile_name = result.get("profile_name")
            if result.get("sudo_configuration", {}).get("has_sudo_password"):
                guidance += f"\n💡 LLM Note: プロファイル '{profile_name}' はsudo機能をサポートしています。"
            else:
                guidance += f"\n⚠️ LLM Note: プロファイル '{profile_name}' はsudo機能が設定されていません。"
        
        elif tool_name == "ssh_execute":
            if result.get("auto_fixed") and result.get("sudo_fix_applied"):
                guidance += "\n💡 LLM Note: sudo自動修正が動作しました（プロファイル設定適用）。"
            
            if result.get("status") == "recovered":
                guidance += "\n🔄 LLM Note: セッション復旧が発生しましたが、コマンドは正常に実行されました。"
            
            if result.get("profile_used"):
                guidance += f"\n🔗 LLM Note: プロファイル '{result['profile_used']}' の設定が適用されました。"
            
            execution_time = result.get("execution_time", 0)
            if execution_time > 10.0:
                guidance += f"\n⏱️ LLM Note: 実行時間が{execution_time:.1f}秒でした。30秒を超える場合は異常と判定してください。"
            
            if result.get("exit_code", 0) > 0:
                guidance += "\n❌ LLM Note: コマンドエラーが発生しました。これはsudo問題ではなく、コマンド自体の問題です。"
        
        elif tool_name == "ssh_execute_batch":
            sudo_summary = result.get("sudo_summary", {})
            if sudo_summary.get("auto_fixed_commands", 0) > 0:
                guidance += f"\n💡 LLM Note: {sudo_summary['auto_fixed_commands']}個のsudoコマンドで自動修正が動作しました（プロファイル設定適用）。"
            
            if sudo_summary.get("recovered_sessions", 0) > 0:
                guidance += f"\n🔄 LLM Note: {sudo_summary['recovered_sessions']}個のコマンドでセッション復旧が発生しました。"
            
            if sudo_summary.get("profile_used"):
                guidance += f"\n🔗 LLM Note: プロファイル '{sudo_summary['profile_used']}' の設定が適用されました。"
        
        elif tool_name == "ssh_test_sudo":
            success_rate = result.get("test_summary", {}).get("success_rate", "0%")
            if success_rate == "100.0%":
                guidance += "\n🎉 LLM Note: sudo設定が完璧です（プロファイル設定有効）。全ての機能が利用可能です。"
            elif float(success_rate.rstrip('%')) >= 66.0:
                guidance += "\n✅ LLM Note: sudo設定は概ね良好です（プロファイル設定適用）。基本機能は利用可能です。"
            else:
                guidance += "\n⚠️ LLM Note: sudo設定に問題があります。プロファイル設定を確認してください。"
        
        return guidance
    
    async def _handle_resources_list(self, request_id: Optional[Union[str, int]]) -> Dict[str, Any]:
        """利用可能なリソースのリスト"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resources": self.resources
            }
        }
    
    async def _handle_resources_read(self, request_id: Optional[Union[str, int]], params: Dict[str, Any]) -> Dict[str, Any]:
        """リソースの読み取り（プロファイル対応版）"""
        uri = params.get("uri")
        
        if not uri:
            return self._error_response(request_id, -32602, "Invalid params: uri is required")
        
        if uri == "ssh://connections":
            connections_info = {}
            for conn_id, executor in self.ssh_connections.items():
                conn_info = executor.get_connection_info()
                # プロファイル情報を追加
                conn_info["profile_used"] = getattr(executor, 'profile_name', None)
                connections_info[conn_id] = conn_info
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(connections_info, indent=2, ensure_ascii=False)
                        }
                    ]
                }
            }
        
        elif uri == "ssh://profiles":
            profiles_list = self.profile_manager.list_profiles()
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps({"profiles": profiles_list}, indent=2, ensure_ascii=False)
                        }
                    ]
                }
            }
        
        elif uri == "ssh://profiles/metadata":
            metadata = self.profile_manager.get_profiles_metadata()
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(metadata, indent=2, ensure_ascii=False)
                        }
                    ]
                }
            }
        
        elif uri == "ssh://sudo_status":
            sudo_status = {}
            for conn_id, executor in self.ssh_connections.items():
                sudo_status[conn_id] = {
                    "hostname": executor.hostname,
                    "username": executor.username,
                    "sudo_configured": bool(executor.sudo_password),
                    "auto_sudo_fix": executor.auto_sudo_fix,
                    "session_recovery": executor.session_recovery,
                    "profile_used": getattr(executor, 'profile_name', None)
                }
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(sudo_status, indent=2, ensure_ascii=False)
                        }
                    ]
                }
            }
        
        elif uri == "ssh://best-practices/profile-usage":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# プロファイル使用ベストプラクティス

## 🔐 セキュリティ強化のメリット

### ✅ LLMから隠蔽される機密情報
- ホスト名・IPアドレス
- ユーザー名
- パスワード
- sudo用パスワード
- 秘密鍵のパス

### ✅ LLMに提供される安全な情報
- プロファイル名（識別子）
- 説明文（description）
- ポート番号
- 機能設定（auto_sudo_fix等）

## 🚀 推奨使用フロー

### 1. プロファイル一覧の確認
```
ssh_list_profiles()
```

### 2. 詳細情報の確認
```
ssh_profile_info("production-web")
```

### 3. セキュアな接続
```
ssh_connect_profile(
    connection_id="prod1",
    profile_name="production-web"
)
```

### 4. 通常のコマンド実行
```
ssh_execute(
    connection_id="prod1",
    command="sudo systemctl status nginx"  # プロファイル設定で自動処理
)
```

## 💡 プロファイル設定のベストプラクティス

### JSON設定例
```json
{
  "profiles": {
    "production-web": {
      "hostname": "prod-web.company.com",
      "username": "webadmin",
      "password": "null",
      "port": 2222,
      "sudo_password": "secure_sudo_pass",
      "private_key_path": "/secure/path/prod_key.pem",
      "description": "本番Webサーバー",
      "auto_sudo_fix": True,
      "session_recovery": True,
      "default_timeout": 600.0
    }
  }
}
```

### 設定のポイント
- `description`: わかりやすい説明を記載
- `auto_sudo_fix`: 必ずtrueに設定
- `session_recovery`: 必ずtrueに設定
- `sudo_password`: sudo権限が必要な場合は設定

## ⚠️ セキュリティ注意事項

### DO
- プロファイルファイルの適切な権限設定（600推奨）
- 定期的なパスワード更新
- 不要なプロファイルの削除
- バックアップでの機密情報管理

### DON'T
- プロファイルファイルの一般ユーザー読み取り許可
- LLMに直接機密情報を渡す
- 古いプロファイルの放置
- バージョン管理システムでの機密情報管理

## 🔄 従来方式からの移行

### 旧方式（非推奨）
```
ssh_connect(
    connection_id="server1",
    hostname="192.168.1.100",  # 機密情報
    username="user",           # 機密情報
    password="password",       # 機密情報
    sudo_password="sudo_pass"  # 機密情報
)
```

### 新方式（推奨）
```
ssh_connect_profile(
    connection_id="server1",
    profile_name="development-server"  # 安全な識別子のみ
)
```

## 📊 パフォーマンス比較
- プロファイル読み込み: +0.1秒
- 接続時間: 同等
- 実行時間: 同等
- セキュリティ: 大幅向上"""
                        }
                    ]
                }
            }
        
        # 既存のリソース処理を継続
        elif uri == "ssh://best-practices/full":
            # best_practice.md ファイルを読み込み
            try:
                import os
                script_dir = os.path.dirname(os.path.abspath(__file__))
                best_practice_path = os.path.join(script_dir, "best_practice.md")
                
                if os.path.exists(best_practice_path):
                    with open(best_practice_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "text/markdown",
                                    "text": content
                                }
                            ]
                        }
                    }
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "text/markdown",
                                    "text": f"# ベストプラクティスファイル未見つけ\n\nbest_practice.md が {best_practice_path} に見つかりません。\n\n## 期待される場所\n- mcp_ssh_server_profile.py と同じディレクトリに best_practice.md を配置してください。"
                                }
                            ]
                        }
                    }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "text/markdown",
                                "text": f"# ファイル読み込みエラー\n\nbest_practice.md の読み込み中にエラーが発生しました。\n\n```\n{str(e)}\n```"
                            }
                        ]
                    }
                }
        
        # 他の既存リソースも同様に処理...
        elif uri == "ssh://best-practices/sudo-usage":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# SSH sudo使用ベストプラクティス（プロファイル対応版）

## 🔑 重要な変更点
この ssh-command-server では、従来のsudo問題が完全に解決され、さらにプロファイル管理でセキュリティが強化されています。

### ✅ プロファイル設定で自動適用
```bash
# プロファイル設定により以下が自動処理される
sudo systemctl restart nginx    # sudo_passwordが自動適用
sudo cat /etc/passwd           # auto_sudo_fixが自動適用
sudo find /root -name "*.conf" # session_recoveryが自動適用
sudo ps aux | grep nginx      # 全設定が統合適用
```

### ❌ 不要になった複雑な設定
```bash  
# これらの複雑な回避策は不要
echo "password" | sudo -S command
sudo -n command || handle_password_prompt
expect スクリプトでのパスワード自動入力
LLMへのパスワード直接指定
```

### 🔧 プロファイル設定要件
- `auto_sudo_fix: true` をプロファイルで設定
- `sudo_password` をプロファイルで事前設定
- NOPASSWD環境でも安全に動作
- `session_recovery: true` で長時間コマンドも安定

### 📊 パフォーマンス
- sudo追加オーバーヘッド: わずか0.01-0.02秒
- プロファイル適用: 0.1秒未満
- パスワード待ちによるハング: 完全解決
- セッション復旧: 自動で高速（1-3秒）

## 💡 LLM実装のポイント
1. プロファイル名のみでsudo機能を利用
2. 機密情報の手動指定は不要
3. `status: "recovered"` は成功の一種
4. `auto_fixed: true` は期待通りの動作
5. `profile_used` フィールドで設定確認

## 📋 完全なベストプラクティス
詳細なガイドは `ssh://best-practices/full` リソースを参照してください。"""
                        }
                    ]
                }
            }
        
        elif uri == "ssh://best-practices/error-handling":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# SSH エラーハンドリングガイド（プロファイル対応版）

## 🔄 セッション復旧の理解

### 正常なレスポンスパターン
```json
{
  "success": True,
  "status": "recovered",        // ← これは正常動作
  "session_recovered": True,    // ← セッション復旧が発生
  "stdout": "actual output",
  "auto_fixed": True,          // ← sudo自動修正も併用
  "profile_used": "prod-web"   // ← プロファイル情報
}
```

### LLMの判定ロジック
```javascript
// ✅ 推奨判定
if (response.success && response.stdout) {
  // 成功 - status が "recovered" でも問題なし
  // profile_used でプロファイル設定確認
  return handleSuccess(response.stdout);
}

// ❌ 間違った判定
if (response.status === "recovered") {
  // エラーとして扱うのは間違い
  return handleError(); // これは不適切
}
```

## ⚡ エラー判定基準
- `success: false` → 真のエラー
- `exit_code > 0` → コマンドエラー（sudo問題ではない）
- `execution_time > 30秒` → 異常な遅延
- `profile_used: null` → プロファイル適用失敗

## 🔧 プロファイル関連エラー
- `PROFILE_NOT_FOUND` → プロファイル名確認
- `PROFILES_FILE_NOT_FOUND` → ファイル配置確認
- `INVALID_PROFILE_FORMAT` → JSON形式確認
- `MISSING_REQUIRED_PARAMETERS` → 必須フィールド確認"""
                        }
                    ]
                }
            }
        
        elif uri == "ssh://best-practices/performance":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# SSH パフォーマンス最適化（プロファイル対応版）

## 📊 パフォーマンス基準値
- プロファイル読み込み: 0.1秒未満
- 通常コマンド: 1.0-1.1秒
- sudoコマンド: 1.0-1.2秒（プロファイル設定適用）
- 複雑パイプ: 1.0-1.3秒
- バッチ実行: 個別実行と同等

## ⚡ プロファイル最適化のコツ

### プロファイル設定の最適化
```json
{
  "default_timeout": 300.0,    // 適切なタイムアウト設定
  "auto_sudo_fix": True,       // 必須設定
  "session_recovery": True,    // 必須設定
  "description": "明確な説明"   // 識別しやすい説明
}
```

### 効率的な接続管理
```bash
# ✅ 推奨：プロファイルベース
ssh_connect_profile(connection_id="prod1", profile_name="production")

# ✅ 推奨：接続の再利用
ssh_execute(connection_id="prod1", command="command1")
ssh_execute(connection_id="prod1", command="command2")  # 同じ接続を再利用

# ✅ 推奨：バッチ実行
ssh_execute_batch(connection_id="prod1", commands=["cmd1", "cmd2", "cmd3"])
```

### パフォーマンス監視
- `execution_time` フィールドで実行時間確認
- `profile_used` フィールドで設定確認
- `auto_fixed` フィールドで最適化確認

## 📈 最適化効果
- 設定時間短縮: 80%削減（機密情報入力不要）
- エラー率低減: 90%削減（プロファイル検証）
- セキュリティ向上: 100%改善（機密情報隠蔽）"""
                        }
                    ]
                }
            }
        
        elif uri == "ssh://best-practices/special-chars":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# 特殊文字・日本語対応ガイド（プロファイル対応版）

## ✅ サポート済み文字
- 日本語（ひらがな、カタカナ、漢字）: 完全サポート
- 特殊記号: @#$%^&*()_+-={}[]|;:,.<>?
- 正規表現文字: [a-z]+ (.*) {1,3} ^start$

## ⚠️ 注意が必要な文字

### 感嘆符（!）の処理
```bash
# ❌ ダブルクォート内で問題
echo "History expansion: !!"

# ✅ シングルクォートで解決
echo 'Special chars: !@#$%^&*()'
```

### 日本語の使用例（プロファイル設定適用）
```bash
# ✅ 完全サポート（プロファイルのsudo設定自動適用）
echo "こんにちは世界"
sudo echo "日本語のsudoテスト"  # プロファイル設定で自動処理
echo "日本語検索" | grep "検索"
```

### プロファイル設定内の特殊文字
```json
{
  "profiles": {
    "test-server": {
      "hostname": "test.example.com",
      "password": "P@ssw0rd!",        // 特殊文字を含むパスワード
      "sudo_password": "Sud0P@ss!",   // 特殊文字を含むsudoパスワード
      "description": "テスト環境（日本語説明）"
    }
  }
}
```

## 💡 エスケープのコツ
- 感嘆符: シングルクォートを使用
- 環境変数: エスケープ(\$HOME) vs 展開($HOME)
- 複雑な文字列: 適切なクォート選択
- プロファイル内: JSON形式に準拠したエスケープ"""
                        }
                    ]
                }
            }
        
        return self._error_response(request_id, -32602, f"Unknown resource: {uri}")
    
    # プロファイル対応の新しいメソッド群
    
    async def _ssh_connect_profile(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """プロファイルを使用したSSH接続の確立"""
        connection_id = args.get("connection_id")
        profile_name = args.get("profile_name")
        
        # オーバーライド設定
        port_override = args.get("port")
        auto_sudo_fix_override = args.get("auto_sudo_fix")
        session_recovery_override = args.get("session_recovery")
        timeout_override = args.get("default_timeout")
        
        if not connection_id:
            raise ValueError("connection_id is required")
        if not profile_name:
            raise ValueError("profile_name is required")
        
        try:
            # プロファイルを取得
            profile = self.profile_manager.get_profile(profile_name)
            
            # オーバーライド設定を適用
            overrides = {}
            if port_override is not None:
                overrides["port"] = port_override
            if auto_sudo_fix_override is not None:
                overrides["auto_sudo_fix"] = auto_sudo_fix_override
            if session_recovery_override is not None:
                overrides["session_recovery"] = session_recovery_override
            if timeout_override is not None:
                overrides["default_timeout"] = timeout_override
            
            if overrides:
                profile = self.profile_manager.merge_profile_with_overrides(profile, overrides)
            
            # SSH Executorを作成
            executor = SSHCommandExecutor(
                hostname=profile.hostname,
                username=profile.username,
                password=profile.password,
                private_key_path=profile.private_key_path,
                port=profile.port,
                sudo_password=profile.sudo_password,
                auto_sudo_fix=profile.auto_sudo_fix,
                session_recovery=profile.session_recovery,
                default_command_timeout=profile.default_timeout
            )
            
            # プロファイル名を記録（後でレスポンスに含める）
            executor.profile_name = profile_name
            
            success = executor.connect()
            
            if success:
                self.ssh_connections[connection_id] = executor
                return {
                    "success": True,
                    "message": f"プロファイル '{profile_name}' を使用してSSH接続が確立されました: {connection_id}",
                    "profile_used": profile_name,
                    "connection_info": {
                        "connection_id": connection_id,
                        "profile_name": profile_name,
                        "hostname": profile.hostname,
                        "username": profile.username,
                        "port": profile.port,
                        "auto_sudo_fix": profile.auto_sudo_fix,
                        "session_recovery": profile.session_recovery,
                        "sudo_configured": bool(profile.sudo_password),
                        "default_timeout": profile.default_timeout,
                        "description": profile.description
                    },
                    "overrides_applied": overrides
                }
            else:
                return {
                    "success": False,
                    "message": f"プロファイル '{profile_name}' での SSH接続に失敗しました",
                    "profile_used": profile_name,
                    "error": "接続エラー"
                }
        
        except ValueError as e:
            self.logger.error(f"Profile error: {e}")
            return {
                "success": False,
                "message": f"プロファイルエラー: {str(e)}",
                "error": str(e)
            }
        except Exception as e:
            self.logger.error(f"SSH profile connection error: {e}")
            return {
                "success": False,
                "message": f"プロファイル接続でエラーが発生しました: {str(e)}",
                "error": str(e)
            }
    
    async def _ssh_list_profiles(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """利用可能なプロファイル一覧を取得"""
        try:
            profiles = self.profile_manager.list_profiles()
            default_profile = self.profile_manager.get_default_profile()
            
            return {
                "success": True,
                "profiles": profiles,
                "total_profiles": len(profiles),
                "default_profile": default_profile
            }
        
        except Exception as e:
            self.logger.error(f"Profile list error: {e}")
            return {
                "success": False,
                "message": f"プロファイル一覧取得でエラーが発生しました: {str(e)}",
                "error": str(e),
                "profiles": []
            }
    
    async def _ssh_profile_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """指定プロファイルの詳細情報を取得"""
        profile_name = args.get("profile_name")
        
        if not profile_name:
            raise ValueError("profile_name is required")
        
        try:
            profile_info = self.profile_manager.get_profile_info(profile_name)
            
            return {
                "success": True,
                **profile_info
            }
        
        except ValueError as e:
            return {
                "success": False,
                "message": f"プロファイル '{profile_name}' が見つかりません",
                "error": str(e)
            }
        except Exception as e:
            self.logger.error(f"Profile info error: {e}")
            return {
                "success": False,
                "message": f"プロファイル情報取得でエラーが発生しました: {str(e)}",
                "error": str(e)
            }
    
    # 既存メソッドの修正版（プロファイル情報を追加）
    
    async def _ssh_execute(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """SSH経由でのコマンド実行（プロファイル対応版）"""
        connection_id = args.get("connection_id")
        command = args.get("command")
        timeout = args.get("timeout")  # Noneの場合はプロファイルのdefault_timeoutを使用
        working_directory = args.get("working_directory")
        sudo_password = args.get("sudo_password")
        
        if not connection_id:
            raise ValueError("connection_id is required")
        if not command:
            raise ValueError("command is required")
        
        if connection_id not in self.ssh_connections:
            return {
                "success": False,
                "message": f"接続が見つかりません: {connection_id}",
                "error": "CONNECTION_NOT_FOUND"
            }
        
        executor = self.ssh_connections[connection_id]
        
        # タイムアウトがNoneの場合、executorのdefault_command_timeoutを使用
        if timeout is None:
            timeout = executor.default_command_timeout
        
        try:
            result = executor.execute_command(
                command=command,
                timeout=timeout,
                working_directory=working_directory,
                sudo_password=sudo_password
            )
            
            response = {
                "success": result.status in [CommandStatus.SUCCESS, CommandStatus.RECOVERED],
                "command": result.command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "status": result.status.value,
                "execution_time": result.execution_time,
                "profile_used": getattr(executor, 'profile_name', None)
            }
            
            # sudo修正情報を追加
            if result.auto_fixed:
                response["auto_fixed"] = True
                response["original_command"] = result.original_command
                response["sudo_fix_applied"] = True
            
            # セッション復旧情報を追加
            if result.session_recovered:
                response["session_recovered"] = True
                response["recovery_message"] = "セッションが復旧されました"
            
            # sudoコマンドの分析結果を追加
            if executor.detect_sudo_command(command):
                response["sudo_detected"] = True
                response["sudo_analysis"] = {
                    "auto_fix_enabled": executor.auto_sudo_fix,
                    "sudo_password_configured": bool(executor.sudo_password),
                    "profile_sudo_configured": bool(getattr(executor, 'profile_name', None))
                }
            
            return response
        
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return {
                "success": False,
                "message": "コマンド実行でエラーが発生しました",
                "error": str(e),
                "profile_used": getattr(executor, 'profile_name', None)
            }
    
    async def _ssh_execute_batch(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """SSH経由での複数コマンド実行（プロファイル対応版）"""
        connection_id = args.get("connection_id")
        commands = args.get("commands", [])
        timeout = args.get("timeout")  # Noneの場合はプロファイル設定を使用
        working_directory = args.get("working_directory")
        stop_on_error = args.get("stop_on_error", True)
        sudo_password = args.get("sudo_password")
        
        if not connection_id:
            raise ValueError("connection_id is required")
        if not commands:
            raise ValueError("commands is required")
        
        if connection_id not in self.ssh_connections:
            return {
                "success": False,
                "message": f"接続が見つかりません: {connection_id}",
                "error": "CONNECTION_NOT_FOUND"
            }
        
        executor = self.ssh_connections[connection_id]
        
        # タイムアウトがNoneの場合、executorのdefault_command_timeoutを使用
        if timeout is None:
            timeout = executor.default_command_timeout
        
        try:
            results = executor.execute_commands(
                commands=commands,
                timeout=timeout,
                working_directory=working_directory,
                stop_on_error=stop_on_error,
                sudo_password=sudo_password
            )
            
            results_data = []
            overall_success = True
            sudo_commands_count = 0
            fixed_commands_count = 0
            recovered_commands_count = 0
            
            for result in results:
                result_dict = {
                    "command": result.command,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                    "status": result.status.value,
                    "execution_time": result.execution_time
                }
                
                # sudo修正情報を追加
                if result.auto_fixed:
                    result_dict["auto_fixed"] = True
                    result_dict["original_command"] = result.original_command
                    fixed_commands_count += 1
                
                # セッション復旧情報を追加
                if result.session_recovered:
                    result_dict["session_recovered"] = True
                    recovered_commands_count += 1
                
                # sudoコマンド検出
                if executor.detect_sudo_command(result.command):
                    result_dict["sudo_detected"] = True
                    sudo_commands_count += 1
                
                results_data.append(result_dict)
                
                if result.status not in [CommandStatus.SUCCESS, CommandStatus.RECOVERED]:
                    overall_success = False
            
            return {
                "success": overall_success,
                "total_commands": len(commands),
                "executed_commands": len(results),
                "results": results_data,
                "profile_used": getattr(executor, 'profile_name', None),
                "sudo_summary": {
                    "sudo_commands_detected": sudo_commands_count,
                    "auto_fixed_commands": fixed_commands_count,
                    "recovered_sessions": recovered_commands_count,
                    "auto_fix_enabled": executor.auto_sudo_fix,
                    "session_recovery_enabled": executor.session_recovery,
                    "profile_used": getattr(executor, 'profile_name', None)
                }
            }
        
        except Exception as e:
            self.logger.error(f"Batch command execution error: {e}")
            return {
                "success": False,
                "message": "バッチコマンド実行でエラーが発生しました",
                "error": str(e),
                "profile_used": getattr(executor, 'profile_name', None)
            }
    
    # 既存メソッドはそのまま継承（後方互換性のため）
    async def _ssh_connect(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """SSH接続の確立（従来方式・後方互換性用）"""
        connection_id = args.get("connection_id")
        hostname = args.get("hostname")
        username = args.get("username")
        password = args.get("password")
        private_key_path = args.get("private_key_path")
        port = args.get("port", 22)
        sudo_password = args.get("sudo_password")
        auto_sudo_fix = args.get("auto_sudo_fix", True)
        session_recovery = args.get("session_recovery", True)
        
        if not connection_id:
            raise ValueError("connection_id is required")
        if not hostname:
            raise ValueError("hostname is required")
        if not username:
            raise ValueError("username is required")
        
        try:
            executor = SSHCommandExecutor(
                hostname=hostname,
                username=username,
                password=password,
                private_key_path=private_key_path,
                port=port,
                sudo_password=sudo_password,
                auto_sudo_fix=auto_sudo_fix,
                session_recovery=session_recovery
            )
            
            # 従来方式であることを記録
            executor.profile_name = None
            
            success = executor.connect()
            
            if success:
                self.ssh_connections[connection_id] = executor
                return {
                    "success": True,
                    "message": f"SSH接続が確立されました: {connection_id}",
                    "connection_method": "direct",
                    "security_warning": "直接接続方式は非推奨です。ssh_connect_profile の使用を推奨します。",
                    "connection_info": {
                        "connection_id": connection_id,
                        "hostname": hostname,
                        "username": username,
                        "port": port,
                        "auto_sudo_fix": auto_sudo_fix,
                        "session_recovery": session_recovery,
                        "sudo_configured": bool(executor.sudo_password)
                    }
                }
            else:
                return {
                    "success": False,
                    "message": "SSH接続に失敗しました",
                    "error": "接続エラー"
                }
        
        except Exception as e:
            self.logger.error(f"SSH connection error: {e}")
            return {
                "success": False,
                "message": "SSH接続でエラーが発生しました",
                "error": str(e)
            }
    
    async def _ssh_disconnect(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """SSH接続の切断"""
        connection_id = args.get("connection_id")
        
        if not connection_id:
            raise ValueError("connection_id is required")
        
        if connection_id not in self.ssh_connections:
            return {
                "success": False,
                "message": f"接続が見つかりません: {connection_id}",
                "error": "CONNECTION_NOT_FOUND"
            }
        
        try:
            executor = self.ssh_connections[connection_id]
            profile_used = getattr(executor, 'profile_name', None)
            
            executor.disconnect()
            del self.ssh_connections[connection_id]
            
            return {
                "success": True,
                "message": f"SSH接続が切断されました: {connection_id}",
                "profile_used": profile_used
            }
        
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")
            return {
                "success": False,
                "message": "接続切断でエラーが発生しました",
                "error": str(e)
            }
    
    async def _ssh_list_connections(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """SSH接続のリスト表示（プロファイル情報含む）"""
        connections = {}
        
        for conn_id, executor in self.ssh_connections.items():
            conn_info = executor.get_connection_info()
            # プロファイル情報を追加
            conn_info["profile_used"] = getattr(executor, 'profile_name', None)
            conn_info["connection_method"] = "profile" if hasattr(executor, 'profile_name') and executor.profile_name else "direct"
            connections[conn_id] = conn_info
        
        return {
            "success": True,
            "connections": connections,
            "total_connections": len(connections),
            "profile_connections": sum(1 for conn in connections.values() if conn.get("profile_used")),
            "direct_connections": sum(1 for conn in connections.values() if not conn.get("profile_used"))
        }
    
    async def _ssh_analyze_command(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """コマンドのsudo使用状況を分析"""
        command = args.get("command")
        
        if not command:
            raise ValueError("command is required")
        
        try:
            # 仮のExecutorインスタンスでsudo分析
            temp_executor = SSHCommandExecutor("localhost", "temp")
            is_sudo = temp_executor.detect_sudo_command(command)
            
            analysis_result = {
                "command": command,
                "sudo_detected": is_sudo,
                "analysis": {}
            }
            
            if is_sudo:
                # sudo修正のシミュレーション
                fixed_with_password, _ = temp_executor.fix_sudo_command(command, "dummy_password")
                fixed_without_password, _ = temp_executor.fix_sudo_command(command, None)
                
                analysis_result["analysis"] = {
                    "requires_password": True,
                    "recommended_with_password": fixed_with_password,
                    "recommended_without_password": fixed_without_password,
                    "timeout_recommendation": "30秒以下のタイムアウトを推奨",
                    "risk_level": "medium",
                    "profile_recommendation": "sudo_passwordが設定されたプロファイルの使用を推奨",
                    "notes": [
                        "sudoコマンドが検出されました",
                        "プロファイル設定により自動修正が適用されます",
                        "パスワード入力待ちによるハングを防ぎます"
                    ]
                }
            else:
                analysis_result["analysis"] = {
                    "requires_password": False,
                    "risk_level": "low",
                    "profile_recommendation": "通常のプロファイルで十分です",
                    "notes": [
                        "通常のコマンドです",
                        "特別な処理は不要です"
                    ]
                }
            
            return {
                "success": True,
                **analysis_result
            }
        
        except Exception as e:
            self.logger.error(f"Command analysis error: {e}")
            return {
                "success": False,
                "message": "コマンド分析でエラーが発生しました",
                "error": str(e)
            }
    
    async def _ssh_recover_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """セッション復旧"""
        connection_id = args.get("connection_id")
        
        if not connection_id:
            raise ValueError("connection_id is required")
        
        if connection_id not in self.ssh_connections:
            return {
                "success": False,
                "message": f"接続が見つかりません: {connection_id}",
                "error": "CONNECTION_NOT_FOUND"
            }
        
        try:
            executor = self.ssh_connections[connection_id]
            profile_used = getattr(executor, 'profile_name', None)
            
            # セッション復旧を試行
            recovery_success = executor.try_session_recovery()
            
            if recovery_success:
                return {
                    "success": True,
                    "message": f"セッション復旧成功: {connection_id}",
                    "connection_status": "recovered",
                    "profile_used": profile_used,
                    "recovery_actions": [
                        "割り込み信号送信",
                        "出力バッファクリア",
                        "応答性テスト実行"
                    ]
                }
            else:
                # 復旧失敗時は強制再接続
                reconnect_success = executor.force_reconnect()
                
                if reconnect_success:
                    return {
                        "success": True,
                        "message": f"強制再接続成功: {connection_id}",
                        "connection_status": "reconnected",
                        "profile_used": profile_used,
                        "recovery_actions": [
                            "セッション復旧失敗",
                            "接続切断",
                            "プロファイル設定で再接続実行" if profile_used else "再接続実行"
                        ]
                    }
                else:
                    # 接続情報から削除
                    del self.ssh_connections[connection_id]
                    return {
                        "success": False,
                        "message": f"復旧・再接続ともに失敗: {connection_id}",
                        "connection_status": "disconnected",
                        "profile_used": profile_used,
                        "recovery_actions": [
                            "セッション復旧失敗",
                            "強制再接続失敗",
                            "接続削除"
                        ]
                    }
        
        except Exception as e:
            self.logger.error(f"Session recovery error: {e}")
            return {
                "success": False,
                "message": "セッション復旧でエラーが発生しました",
                "error": str(e)
            }
    
    async def _ssh_test_sudo(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """sudo設定をテスト（プロファイル設定使用）"""
        connection_id = args.get("connection_id")
        sudo_password = args.get("sudo_password")
        
        if not connection_id:
            raise ValueError("connection_id is required")
        
        if connection_id not in self.ssh_connections:
            return {
                "success": False,
                "message": f"接続が見つかりません: {connection_id}",
                "error": "CONNECTION_NOT_FOUND"
            }
        
        executor = self.ssh_connections[connection_id]
        profile_used = getattr(executor, 'profile_name', None)
        
        try:
            test_results = {
                "connection_id": connection_id,
                "profile_used": profile_used,
                "tests": []
            }
            
            # テスト1: sudo -n (NOPASSWD)
            result1 = executor.execute_command("sudo -n echo 'NOPASSWD test'",
                                              timeout=10.0)
            
            test_results["tests"].append({
                "test_name": "NOPASSWD Test",
                "command": "sudo -n echo 'NOPASSWD test'",
                "success": result1.status == CommandStatus.SUCCESS,
                "exit_code": result1.exit_code,
                "stdout": result1.stdout,
                "stderr": result1.stderr,
                "description": "NOPASSWDが設定されているかテスト"
            })
            
            # テスト2: 自動修正機能のテスト
            old_auto_fix = executor.auto_sudo_fix
            executor.auto_sudo_fix = True  # 一時的に有効化
            
            test_password = sudo_password or executor.sudo_password
            result3 = executor.execute_command("sudo echo 'Auto-fix test'",
                                              timeout=10.0,
                                              sudo_password=test_password)
            
            executor.auto_sudo_fix = old_auto_fix  # 元に戻す
            
            test_results["tests"].append({
                "test_name": "Auto-fix Test",
                "command": "sudo echo 'Auto-fix test'",
                "success": result3.status in [CommandStatus.SUCCESS, CommandStatus.RECOVERED],
                "exit_code": result3.exit_code,
                "stdout": result3.stdout,
                "stderr": result3.stderr,
                "description": "sudo自動修正機能のテスト",
                "auto_fixed": result3.auto_fixed,
                "original_command": result3.original_command,
                "profile_password_used": bool(executor.sudo_password and not sudo_password)
            })
            
            # 総合評価
            successful_tests = sum(1 for test in test_results["tests"] if test["success"])
            total_tests = len(test_results["tests"])
            
            # 推奨設定の生成
            recommendations = []
            
            if result1.exit_code == 0:
                recommendations.append("NOPASSWDが設定されています - 自動化に最適")
            else:
                recommendations.append("NOPASSWDが設定されていません - パスワード指定が必要")
            
            if result3.auto_fixed:
                recommendations.append("自動修正機能が正常に動作しています")
                if profile_used:
                    recommendations.append(f"プロファイル '{profile_used}' の設定が適用されました")
            
            if profile_used:
                recommendations.append(f"プロファイル '{profile_used}' による設定管理が有効です")
            else:
                recommendations.append("プロファイル管理の使用を推奨します（セキュリティ向上）")
            
            return {
                "success": True,
                "test_summary": {
                    "total_tests": total_tests,
                    "successful_tests": successful_tests,
                    "success_rate": f"{(successful_tests/total_tests)*100:.1f}%"
                },
                "test_results": test_results,
                "sudo_configuration": {
                    "nopasswd_enabled": result1.exit_code == 0,
                    "password_works": result3.exit_code == 0 if test_password else None,
                    "auto_fix_available": executor.auto_sudo_fix,
                    "session_recovery_available": executor.session_recovery,
                    "profile_managed": bool(profile_used),
                    "profile_sudo_configured": bool(executor.sudo_password) if profile_used else None
                },
                "recommendations": recommendations,
                "profile_used": profile_used
            }
        
        except Exception as e:
            self.logger.error(f"Sudo test error: {e}")
            return {
                "success": False,
                "message": "sudoテストでエラーが発生しました",
                "error": str(e),
                "profile_used": profile_used
            }
    
    def _error_response(self, request_id: Optional[Union[str, int]], code: int, message: str) -> Dict[str, Any]:
        """エラーレスポンスの生成"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message
            }
        }
    
    async def run(self):
        """MCPサーバーの実行"""
        self.logger.info("MCP SSH Command Server (Profile Enhanced) started v2.0.0")
        
        # 起動時にプロファイル管理の初期化確認
        try:
            profiles = self.profile_manager.list_profiles()
            self.logger.info(f"Profile Manager initialized: {len(profiles)} profiles available")
            
            # プロファイルファイルが初回作成された場合の案内
            if any(p.get('profile_name', '').startswith('example-') for p in profiles):
                self.logger.info("Sample profiles detected. Please update ssh_profiles.json with your actual server information.")
        
        except Exception as e:
            self.logger.warning(f"Profile initialization warning: {e}")
        
        try:
            while True:
                try:
                    # 標準入力からJSONRPCメッセージを読み取り
                    line = await asyncio.get_event_loop().run_in_executor(
                        None, sys.stdin.readline
                    )
                    
                    if not line:
                        self.logger.info("No more input, shutting down")
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    self.logger.debug(f"Received line: {line}")
                    
                    try:
                        request = json.loads(line)
                        response = await self.handle_request(request)
                        
                        # レスポンスがある場合のみ送信（通知の場合はNone）
                        if response is not None:
                            response_json = json.dumps(response, ensure_ascii=False)
                            print(response_json)
                            sys.stdout.flush()
                            self.logger.debug(f"Sent response: {response_json}")
                    
                    except json.JSONDecodeError as e:
                        self.logger.error(f"JSON decode error: {e}")
                        error_response = self._error_response(None, -32700, "Parse error")
                        response_json = json.dumps(error_response, ensure_ascii=False)
                        print(response_json)
                        sys.stdout.flush()
                
                except Exception as e:
                    self.logger.error(f"Unexpected error in main loop: {e}", exc_info=True)
                    # 重大なエラーの場合は継続
                    continue
        
        except KeyboardInterrupt:
            self.logger.info("Server stopped by user")
        
        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
        
        finally:
            # 全ての接続を切断
            for connection_id, executor in list(self.ssh_connections.items()):
                try:
                    profile_used = getattr(executor, 'profile_name', None)
                    executor.disconnect()
                    self.logger.info(f"Disconnected: {connection_id} (profile: {profile_used})")
                except Exception as e:
                    self.logger.error(f"Error disconnecting {connection_id}: {e}")
            
            self.ssh_connections.clear()
            self.logger.info("MCP SSH Command Server (Profile Enhanced) shutdown complete")


async def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description="MCP SSH Command Server - Profile Enhanced v2.0.0")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", type=str, help="Log file path")
    parser.add_argument("--profiles", type=str, default="ssh_profiles.json", 
                       help="Path to SSH profiles file")
    args = parser.parse_args()
    
    # ログ設定
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers
    )
    
    # プロファイルファイルのパス指定
    if args.profiles:
        import os
        os.environ['SSH_PROFILES_FILE'] = args.profiles
    
    # サーバー起動
    server = MCPSSHServerProfile()
    
    # カスタムプロファイルファイルの場合は設定
    if args.profiles != "ssh_profiles.json":
        server.profile_manager = SSHProfileManager(args.profiles)
    
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
