#!/usr/bin/env python3
"""
SSH Profile Manager - セキュアなプロファイル管理
LLMから機密情報を隠しつつ、プロファイル名でサーバー接続を可能にする
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SSHProfile:
    """SSH接続プロファイル"""
    profile_name: str
    hostname: str
    username: str
    password: Optional[str] = None
    port: int = 22
    sudo_password: Optional[str] = None
    private_key_path: Optional[str] = None
    description: str = ""
    auto_sudo_fix: bool = True
    session_recovery: bool = True
    default_timeout: float = 300.0


class SSHProfileManager:
    """
    SSH接続プロファイル管理クラス
    
    機能:
    - プロファイル設定ファイルの読み込み
    - LLM向けの安全な情報提供（機密情報除外）
    - プロファイル検証と取得
    - エラーハンドリング
    """
    
    def __init__(self, profiles_file: str = "ssh_profiles.json"):
        """
        初期化
        
        Args:
            profiles_file: プロファイル設定ファイルのパス
        """
        profiles_json_dir = os.path.dirname(os.path.abspath(__file__))
        profiles_json_path = os.path.join(profiles_json_dir, profiles_file)
        self.profiles_file = profiles_json_path
        self.logger = logging.getLogger(__name__)
        self._profiles_data: Optional[Dict[str, Any]] = None
        self._last_loaded: Optional[float] = None
        
        # プロファイルファイルが存在しない場合、サンプルファイルを作成
        self.logger.info("プロファイル: "+profiles_json_path)

        if not os.path.exists(self.profiles_file):
            logger.info("プロファイルファイルが存在しない")
            sys.exit(1)

    def _create_sample_profile_file(self):
        """サンプルプロファイルファイルを作成"""
        sample_profiles = {
            "profiles": {
                "example-development": {
                    "hostname": "192.168.1.100",
                    "username": "devuser",
                    "password": "dev_password",
                    "port": 22,
                    "sudo_password": "sudo_dev_password",
                    "private_key_path": None,
                    "description": "開発環境サーバー（サンプル）",
                    "auto_sudo_fix": True,
                    "session_recovery": True,
                    "default_timeout": 300.0
                },
                "example-production": {
                    "hostname": "prod.example.com",
                    "username": "produser",
                    "password": None,
                    "port": 2222,
                    "sudo_password": "prod_sudo_password",
                    "private_key_path": "/path/to/prod_key.pem",
                    "description": "本番環境サーバー（サンプル）",
                    "auto_sudo_fix": True,
                    "session_recovery": True,
                    "default_timeout": 600.0
                },
                "example-database": {
                    "hostname": "db.internal.example.com",
                    "username": "dbadmin",
                    "password": "db_password",
                    "port": 22,
                    "sudo_password": "db_sudo_password",
                    "private_key_path": None,
                    "description": "データベースサーバー（サンプル）",
                    "auto_sudo_fix": True,
                    "session_recovery": True,
                    "default_timeout": 300.0
                }
            },
            "default_profile": "example-development",
            "profile_metadata": {
                "version": "1.0",
                "last_updated": datetime.now().isoformat(),
                "created_by": "ssh_profile_manager",
                "note": "これはサンプルファイルです。実際の接続情報に変更してください。"
            }
        }
        
        try:
            with open(self.profiles_file, 'w', encoding='utf-8') as f:
                json.dump(sample_profiles, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"サンプルプロファイルファイルを作成しました: {self.profiles_file}")
            
        except Exception as e:
            self.logger.error(f"サンプルプロファイルファイル作成エラー: {e}")
            raise
    
    def _should_reload_profiles(self) -> bool:
        """プロファイルファイルの再読み込みが必要かチェック"""
        if self._profiles_data is None or self._last_loaded is None:
            return True
        
        try:
            file_mtime = os.path.getmtime(self.profiles_file)
            return file_mtime > self._last_loaded
        except OSError:
            return True
    
    def load_profiles(self) -> Dict[str, Any]:
        """
        プロファイル設定ファイルを読み込み
        
        Returns:
            Dict[str, Any]: プロファイル設定データ
            
        Raises:
            FileNotFoundError: プロファイルファイルが見つからない
            json.JSONDecodeError: JSON形式エラー
            ValueError: 必須フィールド不足
        """
        if not self._should_reload_profiles():
            return self._profiles_data
        
        if not os.path.exists(self.profiles_file):
            raise FileNotFoundError(f"プロファイルファイルが見つかりません: {self.profiles_file}")
        
        try:
            with open(self.profiles_file, 'r', encoding='utf-8') as f:
                profiles_data = json.load(f)
            
            # 基本構造の検証
            if "profiles" not in profiles_data:
                raise ValueError("プロファイルファイルに 'profiles' セクションがありません")
            
            # 各プロファイルの検証
            for profile_name, profile_config in profiles_data["profiles"].items():
                self._validate_profile_config(profile_name, profile_config)
            
            self._profiles_data = profiles_data
            self._last_loaded = os.path.getmtime(self.profiles_file)
            
            self.logger.info(f"プロファイルファイルを読み込みました: {len(profiles_data['profiles'])}個のプロファイル")
            return self._profiles_data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"プロファイルファイルのJSON形式エラー: {e}")
            raise
        except Exception as e:
            self.logger.error(f"プロファイルファイル読み込みエラー: {e}")
            raise
    
    def _validate_profile_config(self, profile_name: str, config: Dict[str, Any]):
        """
        プロファイル設定の検証
        
        Args:
            profile_name: プロファイル名
            config: プロファイル設定
            
        Raises:
            ValueError: 必須フィールド不足または無効な設定
        """
        required_fields = ["hostname", "username"]
        
        for field in required_fields:
            if field not in config or not config[field]:
                raise ValueError(f"プロファイル '{profile_name}' に必須フィールド '{field}' がありません")
        
        # 認証方法の検証
        if not config.get("password") and not config.get("private_key_path"):
            raise ValueError(f"プロファイル '{profile_name}' にパスワードまたは秘密鍵のいずれかが必要です")
        
        # ポート番号の検証
        port = config.get("port", 22)
        if not isinstance(port, int) or port <= 0 or port > 65535:
            raise ValueError(f"プロファイル '{profile_name}' の無効なポート番号: {port}")
    
    def get_profile(self, profile_name: str) -> SSHProfile:
        """
        指定されたプロファイルの完全な設定を取得（機密情報含む）
        
        Args:
            profile_name: プロファイル名
            
        Returns:
            SSHProfile: プロファイル設定
            
        Raises:
            ValueError: プロファイルが見つからない
        """
        profiles_data = self.load_profiles()
        
        if profile_name not in profiles_data["profiles"]:
            available_profiles = list(profiles_data["profiles"].keys())
            raise ValueError(f"プロファイル '{profile_name}' が見つかりません。利用可能: {available_profiles}")
        
        config = profiles_data["profiles"][profile_name]
        
        return SSHProfile(
            profile_name=profile_name,
            hostname=config["hostname"],
            username=config["username"],
            password=config.get("password"),
            port=config.get("port", 22),
            sudo_password=config.get("sudo_password"),
            private_key_path=config.get("private_key_path"),
            description=config.get("description", ""),
            auto_sudo_fix=config.get("auto_sudo_fix", True),
            session_recovery=config.get("session_recovery", True),
            default_timeout=config.get("default_timeout", 300.0)
        )
    
    def list_profiles(self) -> List[Dict[str, Any]]:
        """
        利用可能なプロファイル一覧を取得（LLM向け、機密情報除外）
        
        Returns:
            List[Dict[str, Any]]: プロファイル一覧（機密情報除外）
        """
        try:
            profiles_data = self.load_profiles()
            safe_profiles = []
            
            for profile_name, config in profiles_data["profiles"].items():
                safe_profile = {
                    "profile_name": profile_name,
                    "description": config.get("description", ""),
                    "port": config.get("port", 22),
                    "auto_sudo_fix": config.get("auto_sudo_fix", True),
                    "session_recovery": config.get("session_recovery", True),
                    "default_timeout": config.get("default_timeout", 300.0),
                    "has_password": bool(config.get("password")),
                    "has_private_key": bool(config.get("private_key_path")),
                    "has_sudo_password": bool(config.get("sudo_password"))
                }
                safe_profiles.append(safe_profile)
            
            return safe_profiles
            
        except Exception as e:
            self.logger.error(f"プロファイル一覧取得エラー: {e}")
            return []
    
    def get_profile_info(self, profile_name: str) -> Dict[str, Any]:
        """
        指定されたプロファイルの詳細情報を取得（LLM向け、機密情報除外）
        
        Args:
            profile_name: プロファイル名
            
        Returns:
            Dict[str, Any]: プロファイル詳細情報（機密情報除外）
            
        Raises:
            ValueError: プロファイルが見つからない
        """
        profiles_data = self.load_profiles()
        
        if profile_name not in profiles_data["profiles"]:
            available_profiles = list(profiles_data["profiles"].keys())
            raise ValueError(f"プロファイル '{profile_name}' が見つかりません。利用可能: {available_profiles}")
        
        config = profiles_data["profiles"][profile_name]
        
        return {
            "profile_name": profile_name,
            "description": config.get("description", ""),
            "port": config.get("port", 22),
            "auto_sudo_fix": config.get("auto_sudo_fix", True),
            "session_recovery": config.get("session_recovery", True),
            "default_timeout": config.get("default_timeout", 300.0),
            "authentication": {
                "has_password": bool(config.get("password")),
                "has_private_key": bool(config.get("private_key_path")),
                "private_key_path_set": bool(config.get("private_key_path"))
            },
            "sudo_configuration": {
                "has_sudo_password": bool(config.get("sudo_password")),
                "auto_sudo_fix_enabled": config.get("auto_sudo_fix", True)
            },
            "connection_settings": {
                "port": config.get("port", 22),
                "timeout": config.get("default_timeout", 300.0),
                "session_recovery": config.get("session_recovery", True)
            }
        }
    
    def validate_profile(self, profile_name: str) -> bool:
        """
        プロファイルの存在確認
        
        Args:
            profile_name: プロファイル名
            
        Returns:
            bool: プロファイルが存在するかどうか
        """
        try:
            profiles_data = self.load_profiles()
            return profile_name in profiles_data["profiles"]
        except Exception as e:
            self.logger.error(f"プロファイル検証エラー: {e}")
            return False
    
    def get_default_profile(self) -> Optional[str]:
        """
        デフォルトプロファイル名を取得
        
        Returns:
            Optional[str]: デフォルトプロファイル名
        """
        try:
            profiles_data = self.load_profiles()
            return profiles_data.get("default_profile")
        except Exception as e:
            self.logger.error(f"デフォルトプロファイル取得エラー: {e}")
            return None
    
    def get_profiles_metadata(self) -> Dict[str, Any]:
        """
        プロファイルファイルのメタデータを取得
        
        Returns:
            Dict[str, Any]: メタデータ情報
        """
        try:
            profiles_data = self.load_profiles()
            metadata = profiles_data.get("profile_metadata", {})
            
            # ファイル情報を追加
            file_stat = os.stat(self.profiles_file)
            metadata.update({
                "file_path": os.path.abspath(self.profiles_file),
                "file_size": file_stat.st_size,
                "file_modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                "total_profiles": len(profiles_data["profiles"])
            })
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"メタデータ取得エラー: {e}")
            return {}
    
    def merge_profile_with_overrides(self, profile: SSHProfile, overrides: Dict[str, Any]) -> SSHProfile:
        """
        プロファイル設定にオーバーライド設定をマージ
        
        Args:
            profile: ベースプロファイル
            overrides: オーバーライド設定
            
        Returns:
            SSHProfile: マージされたプロファイル
        """
        # プロファイルを辞書に変換
        profile_dict = {
            "profile_name": profile.profile_name,
            "hostname": profile.hostname,
            "username": profile.username,
            "password": profile.password,
            "port": profile.port,
            "sudo_password": profile.sudo_password,
            "private_key_path": profile.private_key_path,
            "description": profile.description,
            "auto_sudo_fix": profile.auto_sudo_fix,
            "session_recovery": profile.session_recovery,
            "default_timeout": profile.default_timeout
        }
        
        # オーバーライド適用（機密情報は除外）
        safe_override_keys = [
            "port", "auto_sudo_fix", "session_recovery", "default_timeout"
        ]
        
        for key, value in overrides.items():
            if key in safe_override_keys and value is not None:
                profile_dict[key] = value
                self.logger.info(f"プロファイル設定オーバーライド: {key}={value}")
        
        return SSHProfile(**profile_dict)


# テスト用のユーティリティ関数
def test_profile_manager():
    """プロファイルマネージャーのテスト"""
    import logging
    
    # ログ設定
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    try:
        # プロファイルマネージャー初期化
        manager = SSHProfileManager("test_ssh_profiles.json")
        
        # プロファイル一覧表示
        logger.info("=== プロファイル一覧 ===")
        profiles = manager.list_profiles()
        for profile in profiles:
            logger.info(f"プロファイル: {profile['profile_name']}")
            logger.info(f"  説明: {profile['description']}")
            logger.info(f"  ポート: {profile['port']}")
            logger.info(f"  認証: パスワード={profile['has_password']}, 秘密鍵={profile['has_private_key']}")
            logger.info("---")
        
        # 特定プロファイルの詳細情報
        if profiles:
            first_profile = profiles[0]['profile_name']
            logger.info(f"=== {first_profile} 詳細情報 ===")
            info = manager.get_profile_info(first_profile)
            logger.info(json.dumps(info, indent=2, ensure_ascii=False))
        
        # メタデータ表示
        logger.info("=== メタデータ ===")
        metadata = manager.get_profiles_metadata()
        logger.info(json.dumps(metadata, indent=2, ensure_ascii=False))
        
        logger.info("テスト完了")
        
    except Exception as e:
        logger.error(f"テストエラー: {e}")


if __name__ == "__main__":
    test_profile_manager()
