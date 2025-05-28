#!/usr/bin/env python3
"""
MCP SSH Command Server - プロファイル対応版 + ヒアドキュメント自動修正機能

プロファイル管理によりLLMから機密情報を隠蔽し、セキュアなSSH接続を実現
sudo問題修正機能とセッション復旧機能を含む強化版
ヒアドキュメント自動検出・修正機能統合（Phase 1 + Phase 2）
Anthropic社のModel Context Protocol (MCP)に対応したSSHコマンド実行サーバー
JSON-RPC 2.0仕様に完全準拠
"""

import asyncio
import json
import sys
import logging
import re
import time
from typing import Any, Dict, List, Optional, Union, Tuple
from dataclasses import asdict
from enum import Enum
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


# === ヒアドキュメント機能の統合（Phase 1 + Phase 2） ===

class FixAction(Enum):
    """修正アクションの種類"""
    AUTO_APPLIED = "auto_applied"        # 自動適用済み
    SUGGESTION_ONLY = "suggestion_only"  # 提案のみ
    MANUAL_REQUIRED = "manual_required"  # 手動修正必須
    NO_FIX_NEEDED = "no_fix_needed"     # 修正不要


class HeredocDetector:
    """ヒアドキュメント構文検出・自動修正クラス（統合版）"""
    
    def __init__(self):
        self.heredoc_patterns = [
            r'<<\s*(["\']?)(\w+)\1',   # << EOF, << "EOF", << 'EOF'
            r'<<-\s*(["\']?)(\w+)\1',  # <<- EOF (インデント無視形式)
        ]
        
        # 自動修正の設定
        self.auto_fix_settings = {
            "missing_newline": True,        # 改行不足は自動修正
            "simple_indentation": True,     # 簡単なインデント問題は自動修正
            "complex_issues": False         # 複雑な問題は手動修正
        }
    
    def detect_and_fix_heredoc_command(self, command: str, enable_auto_fix: bool = True) -> Dict[str, Any]:
        """
        ヒアドキュメント構文を検出・分析・修正（Phase 1 + Phase 2統合）
        
        Args:
            command: 分析するコマンド文字列
            enable_auto_fix: 自動修正を有効にするか
            
        Returns:
            検出・修正結果の辞書
        """
        result = {
            "is_heredoc": False,
            "markers": [],
            "issues": [],
            "recommendations": [],
            "fixes_applied": [],
            "suggested_fixes": [],
            "fixed_command": command,
            "auto_fix_enabled": enable_auto_fix,
            "analysis_time": None,
            "fix_summary": {}
        }
        
        start_time = time.time()
        
        try:
            # Phase 1: 検出処理
            self._detect_heredoc_issues(result, command)
            
            # Phase 2: 自動修正処理
            if result["is_heredoc"] and enable_auto_fix:
                result["fixed_command"] = self._apply_automatic_fixes(result, command)
            
            # 修正サマリーの生成
            result["fix_summary"] = self._generate_fix_summary(result)
            result["analysis_time"] = time.time() - start_time
            
        except Exception as e:
            result["error"] = f"ヒアドキュメント処理中にエラーが発生: {str(e)}"
        
        return result
    
    def _detect_heredoc_issues(self, result: Dict[str, Any], command: str):
        """ヒアドキュメントの問題を検出"""
        for pattern in self.heredoc_patterns:
            matches = re.finditer(pattern, command, re.MULTILINE)
            for match in matches:
                result["is_heredoc"] = True
                quote_char = match.group(1) if match.group(1) else None
                marker = match.group(2)
                
                marker_info = {
                    "marker": marker,
                    "quoted": bool(quote_char),
                    "quote_type": quote_char,
                    "position": match.span(),
                    "pattern_type": "standard" if "<<-" not in match.group(0) else "indented"
                }
                result["markers"].append(marker_info)
                
                # 個別マーカーの問題を検出
                self._detect_marker_issues(result, marker_info, command)
        
        # 全体的な問題をチェック
        if result["is_heredoc"]:
            self._detect_general_issues(result, command)
            result["recommendations"] = self._generate_recommendations(result)
    
    def _detect_marker_issues(self, result: Dict[str, Any], marker_info: Dict[str, Any], command: str):
        """個別マーカーの問題を検出（修正可能性を含む）"""
        marker = marker_info["marker"]
        
        # 1. エンドマーク後の改行チェック
        if not self._check_heredoc_newline(command, marker):
            issue = {
                "type": "missing_newline",
                "severity": "error",
                "message": f"エンドマーク '{marker}' の後に改行が不足しています",
                "description": "改行不足はタイムアウトの原因になります",
                "marker": marker,
                "auto_fixable": True,  # 安全に自動修正可能
                "fix_action": str(FixAction.AUTO_APPLIED) if self.auto_fix_settings["missing_newline"] else str(FixAction.SUGGESTION_ONLY),
                "suggested_fix": f"{marker}\\n (改行を追加)"
            }
            result["issues"].append(issue)
        
        # 2. マーカーのインデント問題
        indentation_info = self._check_marker_indentation_detailed(command, marker)
        if indentation_info["is_indented"]:
            issue = {
                "type": "indented_marker",
                "severity": "warning",
                "message": f"エンドマーク '{marker}' がインデントされています",
                "description": "エンドマークは行頭から記述することを推奨します",
                "marker": marker,
                "auto_fixable": indentation_info["simple_fix"],
                "fix_action": str(FixAction.AUTO_APPLIED) if (indentation_info["simple_fix"] and self.auto_fix_settings["simple_indentation"]) else str(FixAction.SUGGESTION_ONLY),
                "suggested_fix": f"行頭に移動: {marker}",
                "indentation_details": indentation_info
            }
            result["issues"].append(issue)
    
    def _detect_general_issues(self, result: Dict[str, Any], command: str):
        """全体的な問題を検出"""
        # 複数のヒアドキュメントが存在する場合
        if len(result["markers"]) > 1:
            issue = {
                "type": "multiple_heredocs",
                "severity": "info",
                "message": f"複数のヒアドキュメント ({len(result['markers'])}個) が検出されました",
                "description": "複雑な構文のため注意深く確認してください",
                "auto_fixable": False,
                "fix_action": str(FixAction.MANUAL_REQUIRED),
                "suggested_fix": "個別に確認・修正してください"
            }
            result["issues"].append(issue)
        
        # sudoとの組み合わせチェック
        if re.search(r'\bsudo\b', command):
            issue = {
                "type": "sudo_heredoc_combination",
                "severity": "info",
                "message": "sudoコマンドとヒアドキュメントの組み合わせが検出されました",
                "description": "権限とファイル作成先に注意してください",
                "auto_fixable": False,
                "fix_action": str(FixAction.NO_FIX_NEEDED),
                "suggested_fix": "権限とパスを確認してください"
            }
            result["issues"].append(issue)
    
    def _apply_automatic_fixes(self, result: Dict[str, Any], command: str) -> str:
        """自動修正を適用"""
        fixed_command = command
        
        for issue in result["issues"]:
            if issue.get("auto_fixable") and issue.get("fix_action") == str(FixAction.AUTO_APPLIED):
                
                if issue["type"] == "missing_newline":
                    # 改行不足の修正
                    if not fixed_command.endswith('\n'):
                        fixed_command = fixed_command + '\n'
                        
                        fix_info = {
                            "type": "missing_newline",
                            "marker": issue["marker"],
                            "description": "エンドマーク後に改行を追加",
                            "before": repr(command[-10:]),  # 末尾10文字
                            "after": repr(fixed_command[-10:])
                        }
                        result["fixes_applied"].append(fix_info)
                        issue["fix_applied"] = True
                
                elif issue["type"] == "indented_marker":
                    # インデント問題の修正
                    marker = issue["marker"]
                    indentation_details = issue.get("indentation_details", {})
                    
                    if indentation_details.get("simple_fix"):
                        # 簡単なインデント修正（単純な空白除去）
                        lines = fixed_command.split('\n')
                        for i, line in enumerate(lines):
                            if line.strip() == marker and line != line.lstrip():
                                old_line = line
                                lines[i] = marker  # インデントを除去
                                fixed_command = '\n'.join(lines)
                                
                                fix_info = {
                                    "type": "indented_marker",
                                    "marker": marker,
                                    "description": "エンドマークのインデントを除去",
                                    "before": repr(old_line),
                                    "after": repr(marker)
                                }
                                result["fixes_applied"].append(fix_info)
                                issue["fix_applied"] = True
                                break
            
            else:
                # 自動修正されない問題は提案リストに追加
                if issue.get("fix_action") in [str(FixAction.SUGGESTION_ONLY), str(FixAction.MANUAL_REQUIRED)]:
                    suggestion = {
                        "type": issue["type"],
                        "marker": issue.get("marker"),
                        "severity": issue["severity"],
                        "message": issue["message"],
                        "suggested_fix": issue.get("suggested_fix"),
                        "reason": self._get_fix_reason(issue["type"])
                    }
                    result["suggested_fixes"].append(suggestion)
        
        return fixed_command
    
    def _check_heredoc_newline(self, command: str, marker: str) -> bool:
        """エンドマーク後の改行をチェック"""
        lines = command.split('\n')
        for i, line in enumerate(lines):
            if line.strip() == marker:
                if i < len(lines) - 1:
                    return True
                else:
                    return command.endswith('\n')
        return True
    
    def _check_marker_indentation_detailed(self, command: str, marker: str) -> Dict[str, Any]:
        """エンドマークのインデントを詳細チェック"""
        result = {
            "is_indented": False,
            "simple_fix": False,
            "indentation_type": None,
            "indentation_count": 0
        }
        
        lines = command.split('\n')
        for line in lines:
            if line.strip() == marker and line != line.lstrip():
                result["is_indented"] = True
                
                # インデントの種類と量を分析
                leading_whitespace = line[:len(line) - len(line.lstrip())]
                result["indentation_count"] = len(leading_whitespace)
                
                if leading_whitespace.isspace() and len(leading_whitespace) <= 8:
                    # 8文字以下の空白文字のみなら簡単な修正
                    result["simple_fix"] = True
                    result["indentation_type"] = "simple_whitespace"
                else:
                    # 複雑なインデント（タブ混在など）は手動修正
                    result["simple_fix"] = False
                    result["indentation_type"] = "complex"
                
                break
        
        return result
    
    def _get_fix_reason(self, issue_type: str) -> str:
        """修正が自動適用されない理由を返す"""
        reasons = {
            "multiple_heredocs": "複雑な構文のため個別確認が必要",
            "sudo_heredoc_combination": "権限に関わる問題のため確認が必要",
            "complex_indentation": "複雑なインデントのため手動修正が安全"
        }
        return reasons.get(issue_type, "安全性のため手動確認を推奨")
    
    def _generate_fix_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """修正サマリーを生成"""
        summary = {
            "total_issues": len(result["issues"]),
            "auto_fixed": len(result["fixes_applied"]),
            "suggestions_only": len(result["suggested_fixes"]),
            "manual_required": 0,
            "no_fix_needed": 0,
            "fix_success_rate": 0.0
        }
        
        # 修正アクションの集計
        for issue in result["issues"]:
            action = issue.get("fix_action", str(FixAction.NO_FIX_NEEDED))
            if action == str(FixAction.MANUAL_REQUIRED):
                summary["manual_required"] += 1
            elif action == str(FixAction.NO_FIX_NEEDED):
                summary["no_fix_needed"] += 1
        
        # 修正成功率の計算
        fixable_issues = summary["total_issues"] - summary["no_fix_needed"]
        if fixable_issues > 0:
            summary["fix_success_rate"] = summary["auto_fixed"] / fixable_issues * 100
        
        return summary
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """推奨事項を生成（修正情報付き）"""
        recommendations = []
        
        # 自動修正された項目
        if result["fixes_applied"]:
            recommendations.append(f"✅ {len(result['fixes_applied'])}個の問題を自動修正しました")
            for fix in result["fixes_applied"]:
                recommendations.append(f"  - {fix['description']}")
        
        # 提案のみの項目
        if result["suggested_fixes"]:
            recommendations.append(f"💡 {len(result['suggested_fixes'])}個の修正提案があります")
            for suggestion in result["suggested_fixes"]:
                recommendations.append(f"  - {suggestion['message']}: {suggestion['suggested_fix']}")
        
        # 一般的な推奨事項
        if result["is_heredoc"]:
            recommendations.extend([
                "",
                "📋 ヒアドキュメント一般的なベストプラクティス:",
                "✅ エンドマークの後には必ず改行を入れる",
                "✅ エンドマークは行の先頭から記述（インデントなし）"
            ])
        
        return recommendations
    
    def get_diff_display(self, original_command: str, fixed_command: str) -> Dict[str, Any]:
        """修正前後の差分表示用データを生成"""
        if original_command == fixed_command:
            return {"has_changes": False}
        
        return {
            "has_changes": True,
            "original": original_command,
            "fixed": fixed_command,
            "diff_summary": self._generate_diff_summary(original_command, fixed_command),
            "length_change": len(fixed_command) - len(original_command)
        }
    
    def _generate_diff_summary(self, original: str, fixed: str) -> str:
        """差分のサマリーを生成"""
        changes = []
        
        if not original.endswith('\n') and fixed.endswith('\n'):
            changes.append("末尾に改行を追加")
        
        original_lines = original.split('\n')
        fixed_lines = fixed.split('\n')
        
        if len(original_lines) != len(fixed_lines):
            changes.append(f"行数変更: {len(original_lines)} → {len(fixed_lines)}")
        
        # インデント変更の検出
        for i, (orig_line, fixed_line) in enumerate(zip(original_lines, fixed_lines)):
            if orig_line.strip() == fixed_line.strip() and orig_line != fixed_line:
                changes.append(f"行{i+1}: インデント修正")
        
        return "; ".join(changes) if changes else "軽微な修正"


class MCPSSHServerProfile:
    """MCP対応SSH Command Server - プロファイル対応版 + sudo問題修正 + ヒアドキュメント自動修正統合"""
    
    def __init__(self):
        self.ssh_connections: Dict[str, SSHCommandExecutor] = {}
        self.profile_manager = SSHProfileManager()
        self.logger = logging.getLogger(__name__)
        
        # ヒアドキュメント検出器を初期化（統合版）
        self.heredoc_detector = HeredocDetector()
        
        # ヒアドキュメント自動修正の設定
        self.heredoc_auto_fix_settings = {
            "enabled": True,                    # 自動修正機能の有効/無効
            "safe_fixes_only": True,           # 安全な修正のみ適用
            "missing_newline": True,           # 改行不足の自動修正
            "simple_indentation": True,        # 簡単なインデント修正
            "show_diff": True,                 # 修正前後の差分表示
            "log_fixes": True                  # 修正ログの記録
        }
        
        # MCPツールの定義（プロファイル対応版 + ヒアドキュメント対応）
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
                "description": """SSH経由でコマンドを実行（プロファイル + ヒアドキュメント自動修正対応版）

✅ プロファイル設定の自動適用:
- sudo_password: プロファイル設定を自動使用
- auto_sudo_fix: プロファイル設定に従い自動修正
- session_recovery: プロファイル設定に従い自動復旧
- **heredoc_auto_fix: ヒアドキュメント構文の自動修正**

✅ ヒアドキュメント自動修正機能:
- 改行不足: 自動でエンドマーク後に改行追加
- 簡単なインデント: エンドマークのインデントを自動除去
- 複雑な問題: 安全性のため手動修正を推奨

✅ sudo使用例（プロファイル設定で自動処理）:
- sudo systemctl status nginx     # プロファイルのsudo設定を自動適用
- sudo cat /etc/passwd           # パスワード待ちハング完全解決

🔧 ヒアドキュメント自動修正例:
```bash
# 修正前（問題あり）
cat > /tmp/file << EOF
内容
EOF[改行不足] → 自動で改行追加

# 修正前（インデント問題）
cat > /tmp/file << EOF
内容
    EOF → 自動でインデント除去
```

🔄 レスポンス解釈（統合版）:
- success: true + exit_code: 0 → 正常完了
- **heredoc_auto_fixed: true → ヒアドキュメント自動修正が動作**
- **fixes_applied: [...] → 適用された修正の詳細**
- **suggested_fixes: [...] → 手動修正が必要な提案**
- status: "recovered" → セッション復旧後正常完了
- profile_used: プロファイル名が記録される

📊 パフォーマンス基準:
- 通常コマンド: 1.0-1.1秒
- ヒアドキュメント検出・修正: +0.1秒未満
- sudoコマンド: 1.0-1.2秒（プロファイル設定適用）""",
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
                        },
                        "heredoc_auto_fix": {
                            "type": "boolean",
                            "description": "ヒアドキュメント自動修正の有効/無効（省略時はサーバー設定を使用）"
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
                "description": """コマンドのsudo使用状況とヒアドキュメント構文を分析

💡 LLM向けヒント:
- コマンド実行前の安全性確認に使用
- sudo自動修正の予想結果を事前確認
- **ヒアドキュメント構文の問題を自動検出・修正シミュレーション**
- 複雑なコマンドのリスク評価に活用
- プロファイル設定との整合性確認

🔍 分析結果:
- sudo_detected: sudoコマンドの検出結果
- **heredoc_detected: ヒアドキュメント構文の検出結果**
- **heredoc_issues: ヒアドキュメント使用上の問題点**
- **heredoc_recommendations: 適切な使用方法のガイダンス**
- **auto_fix_preview: 自動修正のプレビュー**
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
            },
            {
                "name": "ssh_configure_heredoc_autofix",
                "description": """ヒアドキュメント自動修正の設定変更

💡 LLM向けヒント:
- 自動修正機能の細かい制御が可能
- 安全性重視の設定が推奨
- 設定変更は即座に反映される

🔧 設定可能項目:
- enabled: 自動修正機能の有効/無効
- safe_fixes_only: 安全な修正のみ適用
- missing_newline: 改行不足の自動修正
- simple_indentation: 簡単なインデント修正
- show_diff: 修正前後の差分表示

⚠️ 安全性の考慮:
- complex_issues: 常にfalse推奨（手動確認が安全）""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "enabled": {
                            "type": "boolean",
                            "description": "自動修正機能の有効/無効"
                        },
                        "safe_fixes_only": {
                            "type": "boolean",
                            "description": "安全な修正のみ適用"
                        },
                        "missing_newline": {
                            "type": "boolean",
                            "description": "改行不足の自動修正"
                        },
                        "simple_indentation": {
                            "type": "boolean",
                            "description": "簡単なインデント修正"
                        },
                        "show_diff": {
                            "type": "boolean",
                            "description": "修正前後の差分表示"
                        }
                    }
                }
            }
        ]
        
        # MCPリソースの定義（プロファイル対応版 + ヒアドキュメント対応）
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
            },
            {
                "uri": "ssh://best-practices/heredoc-usage",
                "name": "ヒアドキュメント使用ベストプラクティス",
                "description": "ヒアドキュメント構文の正しい使い方とよくある問題の回避方法",
                "mimeType": "text/markdown"
            },
            {
                "uri": "ssh://best-practices/heredoc-autofix",
                "name": "ヒアドキュメント自動修正ガイド",
                "description": "自動修正機能の仕組み、安全性、カスタマイズ方法",
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
        self.logger.info("Initializing MCP SSH Server with Profile Support, sudo enhancement, and Heredoc auto-fix")
        
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
                    "name": "ssh-command-server-profile-heredoc-integrated",
                    "version": "2.1.0"
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
        """ツールの実行（プロファイル + ヒアドキュメント対応版）"""
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
            elif tool_name == "ssh_configure_heredoc_autofix":
                result = await self._ssh_configure_heredoc_autofix(arguments)
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
        """LLM向けガイダンスを生成（統合版）"""
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
            # ヒアドキュメント関連のガイダンス
            if result.get("heredoc_analysis"):
                heredoc_info = result["heredoc_analysis"]
                
                if heredoc_info.get("is_heredoc"):
                    marker_count = len(heredoc_info.get("markers", []))
                    guidance += f"\n📝 LLM Note: ヒアドキュメント構文が検出されました（{marker_count}個のマーカー）。"
                    
                    # 自動修正結果の表示
                    if heredoc_info.get("auto_fix_enabled"):
                        fixes_applied = heredoc_info.get("fixes_applied", [])
                        suggested_fixes = heredoc_info.get("suggested_fixes", [])
                        
                        if fixes_applied:
                            guidance += f"\n🔧 LLM Note: {len(fixes_applied)}個の問題を自動修正しました："
                            for fix in fixes_applied:
                                guidance += f"\n   ✅ {fix['description']}"
                        
                        if suggested_fixes:
                            guidance += f"\n💡 LLM Suggestion: {len(suggested_fixes)}個の修正提案があります："
                            for suggestion in suggested_fixes[:2]:  # 最大2つまで表示
                                guidance += f"\n   📋 {suggestion['message']}"
                            if len(suggested_fixes) > 2:
                                guidance += f"\n   📋 （他 {len(suggested_fixes)-2}個の提案あり）"
                        
                        # 修正サマリーの表示
                        fix_summary = heredoc_info.get("fix_summary", {})
                        if fix_summary.get("auto_fixed", 0) > 0:
                            success_rate = fix_summary.get("fix_success_rate", 0)
                            guidance += f"\n📊 LLM Stats: 修正成功率 {success_rate:.1f}%"
                    
                    else:
                        guidance += "\n⚠️ LLM Note: 自動修正が無効です。ssh_configure_heredoc_autofix で有効化できます。"
                    
                    # 差分情報の表示
                    if result.get("heredoc_diff", {}).get("has_changes"):
                        diff_info = result["heredoc_diff"]
                        guidance += f"\n🔄 LLM Diff: コマンドが修正されました（{diff_info.get('diff_summary', '軽微な修正')}）"
            
            # 既存のsudo関連ガイダンス
            if result.get("auto_fixed") and result.get("sudo_fix_applied"):
                guidance += "\n💡 LLM Note: sudo自動修正が動作しました（プロファイル設定適用）。"
            
            if result.get("status") == "recovered":
                guidance += "\n🔄 LLM Note: セッション復旧が発生しましたが、コマンドは正常に実行されました。"
            
            if result.get("profile_used"):
                guidance += f"\n🔗 LLM Note: プロファイル '{result['profile_used']}' の設定が適用されました。"
            
            execution_time = result.get("execution_time", 0)
            if execution_time > 10.0:
                guidance += f"\n⏱️ LLM Note: 実行時間が{execution_time:.1f}秒でした。30秒を超える場合は異常と判定してください。"
            
            exit_code = result.get("exit_code", 0)
            if exit_code is None or exit_code > 0:
                guidance += "\n❌ LLM Note: コマンドエラーが発生しました。これはsudo問題ではなく、コマンド自体の問題です。"
        
        elif tool_name == "ssh_analyze_command":
            # ヒアドキュメント分析結果の表示
            if result.get("heredoc_analysis"):
                heredoc_info = result["heredoc_analysis"]
                if heredoc_info.get("is_heredoc"):
                    guidance += f"\n📝 LLM Note: ヒアドキュメント構文を検出（分析時間: {heredoc_info.get('analysis_time', 0):.3f}秒）。"
                    
                    fix_summary = heredoc_info.get("fix_summary", {})
                    total_issues = fix_summary.get("total_issues", 0)
                    auto_fixable = fix_summary.get("auto_fixed", 0) + len(heredoc_info.get("fixes_applied", []))
                    
                    if total_issues > 0:
                        guidance += f"\n📊 LLM Analysis: {total_issues}個の問題中、{auto_fixable}個が自動修正可能です。"
                    else:
                        guidance += "\n✅ LLM Note: ヒアドキュメント構文に問題はありません。"
                
                # リスク評価の表示
                if result.get("risk_level") == "high":
                    guidance += "\n🔴 LLM Alert: 高リスクコマンドです。特に注意してください。"
                elif result.get("risk_level") == "medium":
                    guidance += "\n🟡 LLM Caution: 中程度のリスクがあります。"
        
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
        
        elif tool_name == "ssh_configure_heredoc_autofix":
            updated_count = len(result.get("updated_settings", {}))
            if updated_count > 0:
                guidance += f"\n🔧 LLM Note: {updated_count}個のヒアドキュメント自動修正設定を更新しました。"
                guidance += "\n💡 LLM Tip: 設定変更は即座に反映されます。"
            else:
                guidance += "\n📋 LLM Note: ヒアドキュメント自動修正の設定は変更されませんでした。"
        
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
        """リソースの読み取り（プロファイル + ヒアドキュメント対応版）"""
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
        
        elif uri == "ssh://best-practices/heredoc-usage":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# ヒアドキュメント使用ベストプラクティス（統合版）

## 🔧 正しいヒアドキュメント構文

### ✅ 正しい使用例
```bash
cat > /tmp/file.txt << EOF
これは正しいヒアドキュメントです。
複数行のテキストを書き込みます。
変数展開も可能: $HOME
EOF
```

### ✅ 正しい使用例
```bash
cat > /tmp/file.txt << 'EOF'
これは正しいヒアドキュメントです。
複数行のテキストを書き込みます。
エンドマーカがクォートされているため、変数展開されません: $HOME
EOF
```

### ❌ よくある間違い

#### 1. エンドマーク後の改行不足（タイムアウトの原因）
```bash
# ❌ 間違い - EOFの後に改行がない
cat > /tmp/file.txt << EOF
内容
EOF[改行なし]

# ✅ 正しい - EOFの後に必ず改行
cat > /tmp/file.txt << EOF
内容
EOF
[改行あり]
```

## 🤖 自動修正機能（統合版）

### ✅ 自動修正される問題
1. **改行不足**: エンドマーク後に自動で改行追加
2. **簡単なインデント**: 単純な空白文字を自動除去

### 💡 提案される問題（手動修正が必要）
1. **複雑な構文**: 安全性のため手動確認を推奨

### 修正例
```bash
# 修正前（自動修正される）
cat > /tmp/file << EOF
内容
EOF[改行不足] → 自動で改行追加

## 🔄 統合システムでの使用フロー

### 1. 事前分析（推奨）
```bash
ssh_analyze_command(command="cat > file << EOF\\n内容\\nEOF")
# → ヒアドキュメント検出 + 修正シミュレーション
```

### 2. 自動修正付き実行
```bash
ssh_execute(command="...", heredoc_auto_fix=True)
# → 自動修正 + 実行 + 結果レポート
```

### 3. 設定カスタマイズ
```bash
ssh_configure_heredoc_autofix(enabled=True, safe_fixes_only=True)
# → 自動修正レベルの調整
```

## 📊 統合システムの利点

### エラー率の削減
- タイムアウトエラーの防止
- 構文エラーの自動修正
- 一貫した品質保証

### 透明性の確保
- 修正前後の差分表示
- 修正理由の詳細説明
- カスタマイズ可能な設定"""
                        }
                    ]
                }
            }
        
        elif uri == "ssh://best-practices/heredoc-autofix":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": """# ヒアドキュメント自動修正ガイド（統合版）

## 🔧 自動修正機能の概要

### ✅ 自動適用される修正（安全な修正のみ）
1. **改行不足の修正**
   - エンドマーク後に改行を自動追加
   - タイムアウト防止に重要

2. **簡単なインデント修正**
   - エンドマークの単純な空白文字を除去
   - 8文字以下の空白のみ対象

### 💡 提案のみの修正（手動確認が必要）
1. **複雑なインデント**
   - タブ混在や複雑な空白パターン
   - 安全性のため手動修正を推奨

## 🔄 自動修正の動作例

### 改行不足の修正
```bash
# 修正前（問題あり）
cat > /tmp/file << EOF
内容
EOF[改行なし]

# 修正後（自動適用）
cat > /tmp/file << EOF
内容
EOF
[改行追加]
```

### レスポンス例
```json
{
  "heredoc_auto_fixed": true,
  "fixes_applied": [
    {
      "type": "missing_newline",
      "description": "エンドマーク後に改行を追加",
      "before": "\"EOF\"",
      "after": "\"EOF\\n\""
    }
  ],
  "fix_summary": {
    "auto_fixed": 1,
    "fix_success_rate": 100.0
  }
}
```

## ⚙️ 設定のカスタマイズ

### ssh_configure_heredoc_autofix での設定
```json
{
  "enabled": true,              // 自動修正機能の有効/無効
  "safe_fixes_only": true,      // 安全な修正のみ適用
  "missing_newline": true,      // 改行不足の自動修正
  "simple_indentation": true,   // 簡単なインデント修正
  "show_diff": true            // 修正前後の差分表示
}
```

### 推奨設定
- ✅ `enabled: true` - 基本機能として有効化
- ✅ `safe_fixes_only: true` - 安全性重視
- ✅ `missing_newline: true` - タイムアウト防止に重要
- ✅ `simple_indentation: true` - 一般的な問題を解決

## 🛡️ 安全性の特徴

### 自動適用される修正（安全確認済み）
1. **改行追加**: 副作用なし
2. **単純なインデント除去**: 構文的に安全

### 提案のみの修正（安全性重視）
1. **複雑な構文**: 意図しない変更のリスク

### リスク軽減機能
- 修正前後の差分表示
- 修正理由の詳細説明
- 修正履歴のログ記録

## 💡 LLM使用時のベストプラクティス

### 推奨フロー
1. `ssh_analyze_command` で事前分析
2. 問題があれば内容を確認
3. `ssh_execute` で自動修正付き実行
4. 修正結果を確認

### 期待される効果
- エラー率の大幅削減
- 繰り返し説明の削除
- 自動的な品質保証
- LLMとユーザーの効率化"""
                        }
                    ]
                }
            }
        
        # 既存のリソース処理
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
        
        # その他の既存リソースも処理...
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
        
        # 他の既存リソースは元の実装を継続...
        
        return self._error_response(request_id, -32602, f"Unknown resource: {uri}")
    
    # === 既存のメソッド群（プロファイル対応）===
    
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
    
    # === ヒアドキュメント対応版の主要メソッド ===
    
    async def _ssh_execute(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """SSH経由でのコマンド実行（ヒアドキュメント自動修正対応版）"""
        connection_id = args.get("connection_id")
        command = args.get("command")
        timeout = args.get("timeout")
        working_directory = args.get("working_directory")
        sudo_password = args.get("sudo_password")
        heredoc_auto_fix = args.get("heredoc_auto_fix")  # 新しいパラメータ
        
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
        
        if timeout is None:
            timeout = executor.default_command_timeout
        
        try:
            # 自動修正設定の決定
            if heredoc_auto_fix is None:
                enable_auto_fix = self.heredoc_auto_fix_settings["enabled"]
            else:
                enable_auto_fix = heredoc_auto_fix
            
            # ヒアドキュメント分析・自動修正を実行
            heredoc_result = self.heredoc_detector.detect_and_fix_heredoc_command(
                command, enable_auto_fix=enable_auto_fix
            )
            
            # 修正されたコマンドを使用
            final_command = heredoc_result["fixed_command"]
            
            # 修正前後の差分情報を生成
            diff_info = None
            if self.heredoc_auto_fix_settings["show_diff"]:
                diff_info = self.heredoc_detector.get_diff_display(command, final_command)
            
            # 元のexecute_commandを実行（修正後のコマンド使用）
            result = executor.execute_command(
                command=final_command,
                timeout=timeout,
                working_directory=working_directory,
                sudo_password=sudo_password
            )
            
            response = {
                "success": result.status in [CommandStatus.SUCCESS, CommandStatus.RECOVERED],
                "command": result.command,
                "original_command": command if final_command != command else None,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "status": result.status.value,
                "execution_time": result.execution_time,
                "profile_used": getattr(executor, 'profile_name', None)
            }
            # 結果にヒアドキュメント情報が自動追加
            if result.heredoc_detected:
                response["heredoc_auto_cleaned"] = True
                response["cleaned_files"] = result.heredoc_files_cleaned

            # ヒアドキュメント分析結果を追加
            if heredoc_result["is_heredoc"]:
                response["heredoc_detected"] = True
                response["heredoc_analysis"] = heredoc_result
                
                # 自動修正が適用された場合
                if heredoc_result["fixes_applied"]:
                    response["heredoc_auto_fixed"] = True
                    response["fixes_applied"] = heredoc_result["fixes_applied"]
                
                # 修正提案がある場合
                if heredoc_result["suggested_fixes"]:
                    response["heredoc_suggestions"] = heredoc_result["suggested_fixes"]
                
                # 差分情報を追加
                if diff_info:
                    response["heredoc_diff"] = diff_info
            
            # 既存のsudo修正情報等を追加
            if result.auto_fixed:
                response["sudo_auto_fixed"] = True
                response["sudo_original_command"] = result.original_command
                response["sudo_fix_applied"] = True
            
            if result.session_recovered:
                response["session_recovered"] = True
                response["recovery_message"] = "セッションが復旧されました"
            
            if executor.detect_sudo_command(command):
                response["sudo_detected"] = True
                response["sudo_analysis"] = {
                    "auto_fix_enabled": executor.auto_sudo_fix,
                    "sudo_password_configured": bool(executor.sudo_password),
                    "profile_sudo_configured": bool(getattr(executor, 'profile_name', None))
                }
            
            # 修正ログの記録
            if self.heredoc_auto_fix_settings["log_fixes"] and heredoc_result.get("fixes_applied"):
                self.logger.info(f"Heredoc auto-fix applied for connection {connection_id}: {len(heredoc_result['fixes_applied'])} fixes")
                for fix in heredoc_result["fixes_applied"]:
                    self.logger.debug(f"  - {fix['type']}: {fix['description']}")
            
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
    
    async def _ssh_analyze_command(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """コマンドのsudo使用状況とヒアドキュメント構文を分析（統合版）"""
        command = args.get("command")
        enable_auto_fix = args.get("enable_auto_fix", True)  # 分析時は修正シミュレーション
        
        if not command:
            raise ValueError("command is required")
        
        try:
            # 仮のExecutorインスタンスでsudo分析
            temp_executor = SSHCommandExecutor("localhost", "temp")
            is_sudo = temp_executor.detect_sudo_command(command)
            
            # ヒアドキュメント分析（修正シミュレーション）
            heredoc_result = self.heredoc_detector.detect_and_fix_heredoc_command(
                command, enable_auto_fix=enable_auto_fix
            )
            
            analysis_result = {
                "command": command,
                "sudo_detected": is_sudo,
                "heredoc_detected": heredoc_result["is_heredoc"],
                "heredoc_analysis": heredoc_result,
                "analysis": {}
            }
            
            # sudo分析（既存）
            if is_sudo:
                fixed_with_password, _ = temp_executor.fix_sudo_command(command, "dummy_password")
                fixed_without_password, _ = temp_executor.fix_sudo_command(command, None)
                
                analysis_result["analysis"]["sudo"] = {
                    "requires_password": True,
                    "recommended_with_password": fixed_with_password,
                    "recommended_without_password": fixed_without_password,
                    "timeout_recommendation": "30秒以下のタイムアウトを推奨",
                    "profile_recommendation": "sudo_passwordが設定されたプロファイルの使用を推奨"
                }
            
            # ヒアドキュメント分析結果の追加（統合版）
            if heredoc_result["is_heredoc"]:
                fix_summary = heredoc_result["fix_summary"]
                
                analysis_result["analysis"]["heredoc"] = {
                    "markers_found": len(heredoc_result["markers"]),
                    "total_issues": fix_summary["total_issues"],
                    "auto_fixable": fix_summary["auto_fixed"],
                    "suggestions_only": fix_summary["suggestions_only"],
                    "manual_required": fix_summary["manual_required"],
                    "fix_success_rate": fix_summary["fix_success_rate"],
                    "fixes_applied": heredoc_result["fixes_applied"],
                    "suggested_fixes": heredoc_result["suggested_fixes"],
                    "recommendations": heredoc_result["recommendations"],
                    "analysis_time": heredoc_result["analysis_time"]
                }
                
                # 修正後のコマンドが異なる場合は差分情報を追加
                if heredoc_result["fixed_command"] != command:
                    diff_info = self.heredoc_detector.get_diff_display(command, heredoc_result["fixed_command"])
                    analysis_result["analysis"]["heredoc"]["diff_preview"] = diff_info
            
            # 総合リスク評価（統合版）
            risk_level = "low"
            risk_factors = []
            
            if is_sudo:
                risk_factors.append("sudo_command")
                risk_level = "medium"
            
            if heredoc_result["is_heredoc"]:
                risk_factors.append("heredoc_syntax")
                
                # エラーレベルの問題があれば高リスク
                error_issues = [i for i in heredoc_result["issues"] if i.get("severity") == "error"]
                unfixable_errors = [i for i in error_issues if not i.get("auto_fixable", False)]
                
                if unfixable_errors:
                    risk_factors.append("heredoc_unfixable_errors")
                    risk_level = "high"
                elif error_issues:
                    risk_factors.append("heredoc_auto_fixable_errors")
                    if risk_level == "low":
                        risk_level = "medium"
                elif heredoc_result["issues"]:
                    risk_factors.append("heredoc_warnings")
                    if risk_level == "low":
                        risk_level = "medium"
            
            analysis_result["risk_level"] = risk_level
            analysis_result["risk_factors"] = risk_factors
            
            # 統合された注意事項（統合版）
            notes = []
            if is_sudo:
                notes.extend([
                    "sudoコマンドが検出されました",
                    "プロファイル設定により自動修正が適用されます"
                ])
            
            if heredoc_result["is_heredoc"]:
                notes.append(f"ヒアドキュメント構文が検出されました（{len(heredoc_result['markers'])}個のマーカー）")
                
                fix_summary = heredoc_result["fix_summary"]
                if fix_summary["auto_fixed"] > 0:
                    notes.append(f"✅ {fix_summary['auto_fixed']}個の問題が自動修正可能です")
                
                if fix_summary["suggestions_only"] > 0:
                    notes.append(f"💡 {fix_summary['suggestions_only']}個の問題に修正提案があります")
                
                if fix_summary["manual_required"] > 0:
                    notes.append(f"⚠️ {fix_summary['manual_required']}個の問題で手動修正が必要です")
                
                if fix_summary["total_issues"] == 0:
                    notes.append("✅ ヒアドキュメント構文は適切です")
            
            if not is_sudo and not heredoc_result["is_heredoc"]:
                notes.append("通常のコマンドです")
            
            analysis_result["notes"] = notes
            
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
    
    async def _ssh_configure_heredoc_autofix(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """ヒアドキュメント自動修正の設定変更"""
        try:
            old_settings = self.heredoc_auto_fix_settings.copy()
            updated_settings = {}
            
            # 設定項目を更新
            for key in ["enabled", "safe_fixes_only", "missing_newline", "simple_indentation", "show_diff"]:
                if key in args:
                    old_value = self.heredoc_auto_fix_settings.get(key)
                    new_value = args[key]
                    self.heredoc_auto_fix_settings[key] = new_value
                    
                    if old_value != new_value:
                        updated_settings[key] = {"old": old_value, "new": new_value}
            
            # ヒアドキュメント検出器の設定も更新
            if "missing_newline" in updated_settings:
                self.heredoc_detector.auto_fix_settings["missing_newline"] = self.heredoc_auto_fix_settings["missing_newline"]
            
            if "simple_indentation" in updated_settings:
                self.heredoc_detector.auto_fix_settings["simple_indentation"] = self.heredoc_auto_fix_settings["simple_indentation"]
            
            return {
                "success": True,
                "message": f"{len(updated_settings)}個の設定を更新しました",
                "updated_settings": updated_settings,
                "current_settings": self.heredoc_auto_fix_settings,
                "recommendations": [
                    "✅ safe_fixes_only: true を推奨（安全性重視）",
                    "✅ missing_newline: true を推奨（タイムアウト防止）",
                ]
            }
        
        except Exception as e:
            self.logger.error(f"Heredoc autofix configuration error: {e}")
            return {
                "success": False,
                "message": "ヒアドキュメント自動修正設定でエラーが発生しました",
                "error": str(e)
            }
    
    # === 既存メソッドはそのまま継承（後方互換性のため）===
    
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
        self.logger.info("MCP SSH Command Server (Profile + Heredoc Integrated) started v2.1.0")
        
        # 起動時にプロファイル管理の初期化確認
        try:
            profiles = self.profile_manager.list_profiles()
            self.logger.info(f"Profile Manager initialized: {len(profiles)} profiles available")
            
            # プロファイルファイルが初回作成された場合の案内
            if any(p.get('profile_name', '').startswith('example-') for p in profiles):
                self.logger.info("Sample profiles detected. Please update ssh_profiles.json with your actual server information.")
        
        except Exception as e:
            self.logger.warning(f"Profile initialization warning: {e}")
        
        # ヒアドキュメント自動修正機能の初期化確認
        self.logger.info(f"Heredoc auto-fix initialized: enabled={self.heredoc_auto_fix_settings['enabled']}")
        
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
            self.logger.info("MCP SSH Command Server (Profile + Heredoc Integrated) shutdown complete")


async def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description="MCP SSH Command Server - Profile + Heredoc Integrated v2.1.0")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", type=str, help="Log file path")
    parser.add_argument("--profiles", type=str, default="ssh_profiles.json", 
                       help="Path to SSH profiles file")
    parser.add_argument("--heredoc-autofix", action="store_true", default=True,
                       help="Enable heredoc auto-fix feature (default: enabled)")
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
    
    # ヒアドキュメント自動修正の初期設定
    if not args.heredoc_autofix:
        server.heredoc_auto_fix_settings["enabled"] = False
        server.heredoc_detector.auto_fix_settings["missing_newline"] = False
        server.heredoc_detector.auto_fix_settings["simple_indentation"] = False
    
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())