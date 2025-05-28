import paramiko
import threading
import time
import uuid
import re
import logging
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class CommandStatus(Enum):
    """コマンド実行ステータス"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    RECOVERED = "recovered"


@dataclass
class CommandResult:
    """コマンド実行結果"""
    stdout: str
    stderr: str
    exit_code: Optional[int]
    status: CommandStatus
    execution_time: float
    command: str
    original_command: Optional[str] = None
    auto_fixed: bool = False
    session_recovered: bool = False
    heredoc_detected: bool = False
    heredoc_files_cleaned: List[str] = None


class SSHCommandExecutor:
    """
    SSH経由でコマンドを実行するためのライブラリ - ヒアドキュメント対応版
    
    特徴:
    - セッション維持
    - マーカー方式による確実なレスポンス終了検出
    - ステータスコード取得
    - タイムアウト対応
    - スレッドセーフ
    - sudo問題自動修正
    - セッション復旧機能
    - **ヒアドキュメント対応（マーカー混入問題解決）**
    """
    
    def __init__(self, 
                 hostname: str, 
                 username: str, 
                 password: Optional[str] = None,
                 private_key_path: Optional[str] = None,
                 port: int = 22,
                 timeout: float = 30.0,
                 default_command_timeout: float = 300.0,
                 sudo_password: Optional[str] = None,
                 auto_sudo_fix: bool = True,
                 session_recovery: bool = True,
                 heredoc_cleanup: bool = True):
        """
        初期化
        
        Args:
            hostname: 接続先ホスト名
            username: ユーザー名
            password: パスワード
            private_key_path: 秘密鍵ファイルパス
            port: SSHポート
            timeout: 接続タイムアウト
            default_command_timeout: デフォルトコマンドタイムアウト
            sudo_password: sudo用パスワード（デフォルトはログインパスワード）
            auto_sudo_fix: sudo問題の自動修正
            session_recovery: セッション復旧機能
            heredoc_cleanup: ヒアドキュメント実行後の自動クリーンアップ
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.port = port
        self.timeout = timeout
        self.default_command_timeout = default_command_timeout
        self.sudo_password = sudo_password or password
        self.auto_sudo_fix = auto_sudo_fix
        self.session_recovery = session_recovery
        self.heredoc_cleanup = heredoc_cleanup
        
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.shell_channel: Optional[paramiko.Channel] = None
        self.is_connected = False
        self._lock = threading.RLock()
        
        # ログ設定
        self.logger = logging.getLogger(__name__)
        
        # マーカー生成用のベース文字列
        self.marker_base = "SSH_CMD_MARKER"
        
        # sudo検出パターン
        self.sudo_patterns = [
            r'\bsudo\s+(?!-[nS]\b)',  # sudo -n, -S以外のsudo
            r'\bsu\s+(?!-c\b)',       # su -c以外のsu
        ]
        
        # ヒアドキュメント検出パターン
        self.heredoc_patterns = [
            r'<<\s*(["\']?)(\w+)\1',   # << EOF, << "EOF", << 'EOF'
            r'<<-\s*(["\']?)(\w+)\1',  # <<- EOF (インデント無視形式)
        ]
        
        # ヒアドキュメントでのファイル作成パターン
        self.heredoc_file_patterns = [
            r'cat\s*>\s*([^\s<&|;]+)',          # cat > /path/to/file
            r'tee\s+([^\s<&|;]+)',              # tee /path/to/file
            r'dd\s+.*of=([^\s<&|;]+)',          # dd of=/path/to/file
            r'(\w+)\s*>\s*([^\s<&|;]+)',        # command > /path/to/file
        ]
    
    def detect_heredoc_command(self, command: str) -> Dict[str, Any]:
        """
        ヒアドキュメント構文を検出し詳細情報を返す
        
        Args:
            command: チェックするコマンド
            
        Returns:
            Dict[str, Any]: 検出結果と詳細情報
        """
        result = {
            "is_heredoc": False,
            "markers": [],
            "target_files": [],
            "command_type": "normal"
        }
        
        # ヒアドキュメントマーカーの検出
        for pattern in self.heredoc_patterns:
            matches = re.finditer(pattern, command, re.MULTILINE)
            for match in matches:
                result["is_heredoc"] = True
                marker_info = {
                    "marker": match.group(2),
                    "quoted": bool(match.group(1)),
                    "quote_type": match.group(1) if match.group(1) else None,
                    "position": match.span(),
                    "pattern_type": "standard" if "<<-" not in match.group(0) else "indented"
                }
                result["markers"].append(marker_info)
        
        # ターゲットファイルの検出
        if result["is_heredoc"]:
            result["target_files"] = self._extract_heredoc_target_files(command)
            
            # コマンドタイプの判定
            if any(cmd in command.lower() for cmd in ["cat >", "tee ", "dd "]):
                result["command_type"] = "file_creation"
            elif any(cmd in command.lower() for cmd in ["cat <<", "cat << EOF"]):
                result["command_type"] = "inline_content"
            else:
                result["command_type"] = "complex"
        
        return result
    
    def _extract_heredoc_target_files(self, command: str) -> List[str]:
        """
        ヒアドキュメントのターゲットファイルを抽出
        
        Args:
            command: コマンド文字列
            
        Returns:
            List[str]: ターゲットファイルのリスト
        """
        files = []
        
        for pattern in self.heredoc_file_patterns:
            matches = re.findall(pattern, command)
            if isinstance(matches, list) and matches:
                if isinstance(matches[0], tuple):
                    # パターンに複数のグループがある場合（最後のグループがファイル名）
                    files.extend([match[-1] for match in matches])
                else:
                    # 単一のグループの場合
                    files.extend(matches)
        
        # ファイルパスのクリーンアップ
        cleaned_files = []
        for file_path in files:
            # クォートの除去
            file_path = file_path.strip("'\"")
            # 基本的な検証
            if file_path and not file_path.startswith('-') and '/' in file_path or not file_path.startswith('.'):
                cleaned_files.append(file_path)
        
        return list(set(cleaned_files))  # 重複除去
    
    def detect_sudo_command(self, command: str) -> bool:
        """
        sudoコマンドを検出
        
        Args:
            command: チェックするコマンド
            
        Returns:
            bool: sudoコマンドかどうか
        """
        for pattern in self.sudo_patterns:
            if re.search(pattern, command):
                return True
        return False
    
    def fix_sudo_command(self, command: str, sudo_password: Optional[str] = None) -> Tuple[str, bool]:
        """
        sudoコマンドを安全な形に修正
        
        Args:
            command: 元のコマンド
            sudo_password: sudo用パスワード
            
        Returns:
            Tuple[str, bool]: (修正されたコマンド, 修正されたかどうか)
        """
        if not self.auto_sudo_fix or not self.detect_sudo_command(command):
            return command, False
        
        original_command = command
        password = sudo_password or self.sudo_password
        
        if password and 'sudo ' in command and '-S' not in command:
            # パスワードがある場合: sudo -S オプションでパスワードをstdin経由で渡す
            command = re.sub(r'\bsudo\s+', 'sudo -S ', command)
            command = f"echo '{password}' | {command}"
            self.logger.info(f"sudo修正(パスワード付き): {original_command}")
            return command, True
            
        elif 'sudo ' in command and '-n' not in command and '-S' not in command:
            # パスワードがない場合: sudo -n オプションでNOPASSWDチェック
            command = re.sub(r'\bsudo\s+', 'sudo -n ', command)
            self.logger.info(f"sudo修正(-n オプション): {original_command}")
            return command, True
        
        return command, False
    
    def clean_heredoc_files(self, target_files: List[str], marker_base: str) -> List[str]:
        """
        ヒアドキュメントで作成されたファイルからマーカーを除去
        
        Args:
            target_files: クリーンアップ対象のファイルリスト
            marker_base: 除去するマーカーのベース文字列
            
        Returns:
            List[str]: クリーンアップされたファイルのリスト
        """
        cleaned_files = []
        print("ヒアドキュメントのクリーンアップ関数 clean_heredoc_files() が呼ばれました")
        for file_path in target_files:
            try:
                # マーカーパターンの生成
                marker_pattern = f"{marker_base}_[A-Z]+_[a-f0-9]+"
                
                # sedコマンドでマーカーを除去
                cleanup_command = f"sed -i '/{marker_pattern}/d' '{file_path}'"
                
                # 直接実行（マーカーなし方式）
                result = self._execute_direct_command(cleanup_command, timeout=10.0)
                
                if result.status == CommandStatus.SUCCESS:
                    cleaned_files.append(file_path)
                    self.logger.info(f"ヒアドキュメントファイルをクリーンアップ: {file_path}")
                else:
                    self.logger.warning(f"ファイルクリーンアップ失敗: {file_path} - {result.stderr}")
                    
            except Exception as e:
                self.logger.error(f"ファイルクリーンアップエラー {file_path}: {e}")
        
        return cleaned_files
    
    def _execute_direct_command(self, command: str, timeout: float = 30.0) -> CommandResult:
        """
        マーカーなしでコマンドを直接実行（クリーンアップ用）
        
        Args:
            command: 実行するコマンド
            timeout: タイムアウト時間
            
        Returns:
            CommandResult: 実行結果
        """
        start_time = time.time()
        
        try:
            # プロンプト確認用のテストコマンド
            test_id = uuid.uuid4().hex[:6]
            test_echo = f"echo DIRECT_TEST_{test_id}"
            
            # 既存出力をクリア
            self._drain_output()
            
            # テストコマンド送信
            self.shell_channel.send(test_echo + '\n')
            time.sleep(0.5)
            
            # 実際のコマンド送信
            self.shell_channel.send(command + '\n')
            
            # 完了確認用のコマンド送信
            confirm_id = uuid.uuid4().hex[:6]
            confirm_echo = f"echo DIRECT_DONE_{confirm_id}"
            self.shell_channel.send(confirm_echo + '\n')
            
            # 出力収集
            output_lines = []
            found_start = False
            found_end = False
            end_time = start_time + timeout
            
            while time.time() < end_time and not found_end:
                try:
                    data = self.shell_channel.recv(4096)
                    if not data:
                        time.sleep(0.1)
                        continue
                    
                    output = data.decode('utf-8', errors='ignore')
                    lines = output.split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        
                        if f"DIRECT_TEST_{test_id}" in line:
                            found_start = True
                            continue
                        elif f"DIRECT_DONE_{confirm_id}" in line:
                            found_end = True
                            break
                        elif found_start and not found_end and line:
                            # プロンプト文字列をフィルタリング
                            if not any(prompt in line for prompt in ['$', '#', '>', '%']):
                                output_lines.append(line)
                
                except Exception:
                    time.sleep(0.1)
                    continue
            
            execution_time = time.time() - start_time
            stdout_text = '\n'.join(output_lines)
            
            # ステータス判定
            if found_end:
                status = CommandStatus.SUCCESS
            elif time.time() >= end_time:
                status = CommandStatus.TIMEOUT
            else:
                status = CommandStatus.ERROR
            
            return CommandResult(
                stdout=stdout_text,
                stderr="",
                exit_code=0 if status == CommandStatus.SUCCESS else 1,
                status=status,
                execution_time=execution_time,
                command=command
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResult(
                stdout="",
                stderr=str(e),
                exit_code=None,
                status=CommandStatus.ERROR,
                execution_time=execution_time,
                command=command
            )
    
    def execute_heredoc_command(self, 
                               command: str, 
                               timeout: Optional[float] = None,
                               working_directory: Optional[str] = None,
                               sudo_password: Optional[str] = None) -> CommandResult:
        """
        ヒアドキュメント専用の実行メソッド（マーカー混入回避）
        
        Args:
            command: ヒアドキュメントコマンド
            timeout: タイムアウト時間
            working_directory: 作業ディレクトリ
            sudo_password: sudo用パスワード
            
        Returns:
            CommandResult: 実行結果
        """
        if timeout is None:
            timeout = self.default_command_timeout
        
        start_time = time.time()
        original_command = command
        auto_fixed = False
        session_recovered = False
        
        # ヒアドキュメント詳細情報を取得
        heredoc_info = self.detect_heredoc_command(command)
        
        # sudo問題の自動修正
        if self.detect_sudo_command(command):
            fixed_command, was_fixed = self.fix_sudo_command(command, sudo_password)
            if was_fixed:
                command = fixed_command
                auto_fixed = True
                timeout = min(timeout, 30.0)
        
        with self._lock:
            if not self.is_connected or not self.shell_channel:
                return CommandResult(
                    stdout="",
                    stderr="SSH接続が確立されていません",
                    exit_code=None,
                    status=CommandStatus.ERROR,
                    execution_time=0.0,
                    command=original_command,
                    original_command=original_command,
                    auto_fixed=auto_fixed,
                    session_recovered=False,
                    heredoc_detected=True
                )
            
            try:
                # 作業ディレクトリの変更
                if working_directory:
                    cd_command = f"cd '{working_directory}'"
                    cd_result = self._execute_direct_command(cd_command, timeout=10.0)
                    if cd_result.status != CommandStatus.SUCCESS:
                        self.logger.warning(f"作業ディレクトリ変更失敗: {working_directory}")
                
                # 既存の出力をクリア
                self._drain_output()
                
                # ヒアドキュメント実行用の特別な処理
                completion_marker = f"HEREDOC_COMPLETE_{uuid.uuid4().hex[:8]}"
                
                # ヒアドキュメントコマンド + 完了マーカーを一括送信
                full_command = f"{command} && echo '{completion_marker}'"
                print("full cmd: ", full_command)
                self.logger.info(f"ヒアドキュメント実行開始: {original_command}")
                self.shell_channel.send(full_command + '\n')
                
                # 出力収集（完了マーカーを待つ）
                output_lines = []
                stderr_lines = []
                command_completed = False
                end_time = start_time + timeout
                
                while time.time() < end_time and not command_completed:
                    try:
                        data = self.shell_channel.recv(4096)
                        if not data:
                            time.sleep(0.1)
                            continue
                        
                        output = data.decode('utf-8', errors='ignore')
                        lines = output.split('\n')
                        
                        for line in lines:
                            line = line.strip()
                            
                            # 完了マーカーの検出
                            if completion_marker in line:
                                print("完了マーカーを検出しました")
                                command_completed = True
                                break
                            
                            # 出力の収集（プロンプトや制御文字を除外）
                            if line is not None and not line.startswith(('$', '#', '>', '%')):
                                # エラーメッセージの検出
                                if any(error_word in line.lower() for error_word in ['error', 'permission denied', 'no such file']):
                                    stderr_lines.append(line)
                                else:
                                    output_lines.append(line)
                        
                        if command_completed:
                            break
                            
                    except Exception as e:
                        time.sleep(0.1)
                        continue
                
                execution_time = time.time() - start_time
                
                # 結果の処理
                stdout_text = '\n'.join(output_lines)
                stderr_text = '\n'.join(stderr_lines)
                
                # ステータス判定
                if command_completed:
                    status = CommandStatus.SUCCESS
                    exit_code = 0
                elif time.time() >= end_time:
                    status = CommandStatus.TIMEOUT
                    exit_code = 124  # timeout exit code
                    
                    # タイムアウト時の復旧処理
                    self.logger.warning(f"ヒアドキュメントコマンドタイムアウト、復旧を試行: {original_command}")
                    if self.try_session_recovery():
                        status = CommandStatus.RECOVERED
                        session_recovered = True
                        stderr_text += "\n[セッション復旧成功]"
                    else:
                        stderr_text += "\n[セッション復旧失敗]"
                else:
                    status = CommandStatus.ERROR
                    exit_code = 1
                
                # ファイルクリーンアップ（成功時のみ）
                cleaned_files = []
                """
                if (status == CommandStatus.SUCCESS and 
                    self.heredoc_cleanup and 
                    heredoc_info["target_files"]):
                    
                    self.logger.info(f"ヒアドキュメントファイルクリーンアップ開始: {heredoc_info['target_files']}")
                    cleaned_files = self.clean_heredoc_files(
                        heredoc_info["target_files"], 
                        self.marker_base
                    )
                """
                
                return CommandResult(
                    stdout=stdout_text,
                    stderr=stderr_text,
                    exit_code=exit_code,
                    status=status,
                    execution_time=execution_time,
                    command=original_command,
                    original_command=original_command if auto_fixed else None,
                    auto_fixed=auto_fixed,
                    session_recovered=session_recovered,
                    heredoc_detected=True,
                    heredoc_files_cleaned=cleaned_files
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                self.logger.error(f"ヒアドキュメントコマンド実行エラー: {e}")
                return CommandResult(
                    stdout="",
                    stderr=str(e),
                    exit_code=None,
                    status=CommandStatus.ERROR,
                    execution_time=execution_time,
                    command=original_command,
                    original_command=original_command if auto_fixed else None,
                    auto_fixed=auto_fixed,
                    session_recovered=False,
                    heredoc_detected=True
                )
    
    def send_interrupt_signals(self):
        """
        セッションに割り込み信号を送信
        """
        try:
            if self.shell_channel and self.shell_channel.active:
                # 複数の割り込み信号を順次送信
                interrupt_signals = [
                    '\x03',    # Ctrl+C
                    '\x1b',    # ESC
                    '\n',      # Enter
                    '\x03\n',  # Ctrl+C + Enter
                    'q\n',     # q + Enter (一部のプログラム用)
                ]
                
                for signal in interrupt_signals:
                    self.shell_channel.send(signal)
                    time.sleep(0.3)
                
                self.logger.info("割り込み信号を送信しました")
        except Exception as e:
            self.logger.error(f"割り込み信号送信エラー: {e}")
    
    def test_session_responsiveness(self) -> bool:
        """
        セッションの応答性をテスト
        
        Returns:
            bool: セッションが応答するかどうか
        """
        try:
            test_id = uuid.uuid4().hex[:8]
            test_marker = f"RECOVERY_TEST_{test_id}"
            test_command = f"echo '{test_marker}'"
            
            self.shell_channel.send(test_command + '\n')
            
            # 応答を待つ
            start_time = time.time()
            collected_output = ""
            
            while time.time() - start_time < 3:
                try:
                    data = self.shell_channel.recv(1024)
                    if data:
                        output = data.decode('utf-8', errors='ignore')
                        collected_output += output
                        if test_marker in output:
                            self.logger.info("セッション応答性テスト成功")
                            return True
                except:
                    pass
                time.sleep(0.1)
            
            self.logger.warning(f"セッション応答性テスト失敗: {collected_output}")
            return False
            
        except Exception as e:
            self.logger.error(f"セッション応答性テストエラー: {e}")
            return False
    
    def try_session_recovery(self) -> bool:
        """
        セッション復旧を試行
        
        Returns:
            bool: 復旧成功フラグ
        """
        if not self.session_recovery:
            return False
        
        try:
            self.logger.info("セッション復旧を開始します")
            
            # 1. 割り込み信号送信
            self.send_interrupt_signals()
            
            # 2. 出力バッファクリア
            self._drain_output()
            
            # 3. 応答性テスト
            if self.test_session_responsiveness():
                self.logger.info("セッション復旧成功")
                return True
            
            # 4. 追加の復旧試行
            self.logger.info("追加復旧処理を実行")
            for _ in range(2):
                self.send_interrupt_signals()
                time.sleep(1)
                self._drain_output()
                
                if self.test_session_responsiveness():
                    self.logger.info("追加復旧処理で成功")
                    return True
            
            self.logger.warning("セッション復旧失敗")
            return False
            
        except Exception as e:
            self.logger.error(f"セッション復旧エラー: {e}")
            return False
    
    def force_reconnect(self) -> bool:
        """
        強制的に再接続
        
        Returns:
            bool: 再接続成功フラグ
        """
        self.logger.info("強制再接続を実行します")
        
        # 現在の接続を切断
        self.disconnect()
        
        # 少し待ってから再接続
        time.sleep(2)
        
        return self.connect()
    
    def connect(self) -> bool:
        """
        SSH接続を確立
        
        Returns:
            bool: 接続成功フラグ
        """
        with self._lock:
            try:
                # SSH クライアント作成
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # 認証方法の決定
                auth_kwargs = {}
                if self.private_key_path:
                    auth_kwargs['key_filename'] = self.private_key_path
                elif self.password:
                    auth_kwargs['password'] = self.password
                else:
                    raise ValueError("パスワードまたは秘密鍵が必要です")
                
                # 接続
                self.ssh_client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    timeout=self.timeout,
                    **auth_kwargs
                )
                
                # インタラクティブシェルを開始
                self.shell_channel = self.ssh_client.invoke_shell()
                self.shell_channel.settimeout(1.0)  # ノンブロッキング読み取り用
                
                # 初期プロンプトを待つ
                time.sleep(1.0)
                self._drain_output()
                
                self.is_connected = True
                self.logger.info(f"SSH接続が確立されました: {self.hostname}")
                return True
                
            except Exception as e:
                self.logger.error(f"SSH接続エラー: {e}")
                self.disconnect()
                return False
    
    def disconnect(self):
        """SSH接続を切断"""
        with self._lock:
            try:
                if self.shell_channel:
                    self.shell_channel.close()
                    self.shell_channel = None
                
                if self.ssh_client:
                    self.ssh_client.close()
                    self.ssh_client = None
                
                self.is_connected = False
                self.logger.info("SSH接続が切断されました")
                
            except Exception as e:
                self.logger.error(f"切断エラー: {e}")
    
    def is_alive(self) -> bool:
        """
        接続が生きているかチェック
        
        Returns:
            bool: 接続状態
        """
        with self._lock:
            if not self.is_connected or not self.shell_channel:
                return False
            
            try:
                # 軽量なコマンドで接続確認
                result = self.execute_command("echo connection_check", timeout=5.0)
                return result.status in [CommandStatus.SUCCESS, CommandStatus.RECOVERED]
            except:
                return False
    
    def execute_command(self, 
                       command: str, 
                       timeout: Optional[float] = None,
                       working_directory: Optional[str] = None,
                       sudo_password: Optional[str] = None) -> CommandResult:
        """
        コマンドを実行（ヒアドキュメント対応 + sudo問題修正版）
        
        Args:
            command: 実行するコマンド
            timeout: タイムアウト時間（秒）
            working_directory: 作業ディレクトリ
            sudo_password: sudo用パスワード（一時的に指定）
            
        Returns:
            CommandResult: 実行結果
        """
        # ヒアドキュメント検出と分岐
        heredoc_info = self.detect_heredoc_command(command)
        
        if heredoc_info["is_heredoc"]:
            print(f"ヒアドキュメント検出: ")
            print("cmd: ", command)
            self.logger.info(f"ヒアドキュメント検出: {command[:50]}...")
            return self.execute_heredoc_command(
                command=command,
                timeout=timeout,
                working_directory=working_directory,
                sudo_password=sudo_password
            )
        else:
            print(f"normal command")
            print("cmd: ", command)
            return self._execute_normal_command(
                command=command,
                timeout=timeout,
                working_directory=working_directory,
                sudo_password=sudo_password
            )
    
    def _execute_normal_command(self, 
                               command: str, 
                               timeout: Optional[float] = None,
                               working_directory: Optional[str] = None,
                               sudo_password: Optional[str] = None) -> CommandResult:
        """
        通常コマンドの実行（既存のマーカー方式）
        
        Args:
            command: 実行するコマンド
            timeout: タイムアウト時間（秒）
            working_directory: 作業ディレクトリ
            sudo_password: sudo用パスワード（一時的に指定）
            
        Returns:
            CommandResult: 実行結果
        """
        if timeout is None:
            timeout = self.default_command_timeout
        
        original_command = command
        start_time = time.time()
        auto_fixed = False
        session_recovered = False
        
        # sudo問題の自動修正
        if self.detect_sudo_command(command):
            fixed_command, was_fixed = self.fix_sudo_command(command, sudo_password)
            if was_fixed:
                command = fixed_command
                auto_fixed = True
                # sudoコマンドは短いタイムアウトに設定
                timeout = min(timeout, 30.0)
        
        with self._lock:
            if not self.is_connected or not self.shell_channel:
                return CommandResult(
                    stdout="",
                    stderr="SSH接続が確立されていません",
                    exit_code=None,
                    status=CommandStatus.ERROR,
                    execution_time=0.0,
                    command=original_command,
                    original_command=original_command,
                    auto_fixed=auto_fixed,
                    session_recovered=False
                )
            
            try:
                # 作業ディレクトリの変更
                if working_directory:
                    cd_command = f"cd '{working_directory}'"
                    command = f"{cd_command} && {command}"
                
                # 一意のマーカーを生成
                marker_id = str(uuid.uuid4()).replace('-', '')
                start_marker = f"{self.marker_base}_START_{marker_id}"
                end_marker = f"{self.marker_base}_END_{marker_id}"
                
                # コマンド構築（マーカーとステータスコード取得を含む）
                full_command = (
                    f"echo '{start_marker}' && "
                    f"({command}); "
                    f"exit_code=$?; "
                    f"echo '{end_marker}'; "
                    f"echo 'EXIT_CODE:'$exit_code"
                )
                
                # 既存の出力をクリア
                self._drain_output()
                
                # コマンド送信
                self.shell_channel.send(full_command + '\n')
                
                # 出力を収集
                stdout_lines = []
                stderr_lines = []
                exit_code = None
                command_started = False
                command_ended = False
                
                end_time = start_time + timeout
                
                while time.time() < end_time:
                    try:
                        data = self.shell_channel.recv(4096)
                        if not data:
                            time.sleep(0.1)
                            continue
                        
                        output = data.decode('utf-8', errors='ignore')
                        lines = output.split('\n')
                        
                        for line in lines:
                            line = line.strip()
                            
                            # マーカー検出
                            if start_marker in line:
                                command_started = True
                                continue
                            elif end_marker in line:
                                command_ended = True
                                continue
                            elif line.startswith('EXIT_CODE:'):
                                try:
                                    exit_code = int(line.split(':', 1)[1])
                                except (ValueError, IndexError):
                                    pass
                                break
                            
                            # コマンド実行中の出力を収集
                            if command_started and not command_ended and line:
                                stdout_lines.append(line)
                        
                        # 終了条件チェック
                        if command_ended and exit_code is not None:
                            break
                            
                    except paramiko.ssh_exception.SSHException:
                        break
                    except Exception:
                        time.sleep(0.1)
                        continue
                
                execution_time = time.time() - start_time
                
                # 結果の組み立て
                stdout_text = '\n'.join(stdout_lines)
                stderr_text = '\n'.join(stderr_lines)
                
                # ステータス判定
                if not command_started:
                    status = CommandStatus.ERROR
                elif time.time() >= end_time:
                    status = CommandStatus.TIMEOUT
                    # タイムアウト時の復旧処理
                    self.logger.warning(f"コマンドタイムアウト、復旧を試行: {original_command}")
                    if self.try_session_recovery():
                        status = CommandStatus.RECOVERED
                        session_recovered = True
                        stderr_text += "\n[セッション復旧成功]"
                    else:
                        stderr_text += "\n[セッション復旧失敗]"
                        # 復旧失敗時は強制再接続を試行
                        if self.force_reconnect():
                            stderr_text += "\n[強制再接続成功]"
                        else:
                            stderr_text += "\n[強制再接続失敗: 接続切断]"
                            self.is_connected = False
                else:
                    status = CommandStatus.SUCCESS
                
                return CommandResult(
                    stdout=stdout_text,
                    stderr=stderr_text,
                    exit_code=exit_code,
                    status=status,
                    execution_time=execution_time,
                    command=original_command,
                    original_command=original_command if auto_fixed else None,
                    auto_fixed=auto_fixed,
                    session_recovered=session_recovered
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                self.logger.error(f"コマンド実行エラー: {e}")
                return CommandResult(
                    stdout="",
                    stderr=str(e),
                    exit_code=None,
                    status=CommandStatus.ERROR,
                    execution_time=execution_time,
                    command=original_command,
                    original_command=original_command if auto_fixed else None,
                    auto_fixed=auto_fixed,
                    session_recovered=False
                )
    
    def execute_commands(self, 
                        commands: list, 
                        timeout: Optional[float] = None,
                        working_directory: Optional[str] = None,
                        stop_on_error: bool = True,
                        sudo_password: Optional[str] = None) -> list[CommandResult]:
        """
        複数のコマンドを順次実行（ヒアドキュメント対応 + sudo問題修正版）
        
        Args:
            commands: コマンドのリスト
            timeout: 各コマンドのタイムアウト時間
            working_directory: 作業ディレクトリ
            stop_on_error: エラー時に停止するかどうか
            sudo_password: sudo用パスワード
            
        Returns:
            list[CommandResult]: 実行結果のリスト
        """
        results = []
        current_dir = working_directory
        
        for command in commands:
            result = self.execute_command(
                command, 
                timeout=timeout, 
                working_directory=current_dir,
                sudo_password=sudo_password
            )
            results.append(result)
            
            # エラー時の処理（RECOVEREDは継続）
            if stop_on_error and result.status not in [CommandStatus.SUCCESS, CommandStatus.RECOVERED]:
                break
            
            # cdコマンドの場合、作業ディレクトリを更新
            if command.strip().startswith('cd '):
                if result.status in [CommandStatus.SUCCESS, CommandStatus.RECOVERED]:
                    # 相対パスの場合の処理は簡略化
                    new_dir = command.strip()[3:].strip()
                    if new_dir.startswith('/'):
                        current_dir = new_dir
                    else:
                        # 簡単な相対パス処理
                        if current_dir:
                            current_dir = f"{current_dir}/{new_dir}"
                        else:
                            current_dir = new_dir
        
        return results
    
    def _drain_output(self) -> str:
        """
        チャンネルの残存出力をクリア
        
        Returns:
            str: クリアされた出力
        """
        output = ""
        try:
            while True:
                data = self.shell_channel.recv(4096)
                if not data:
                    break
                output += data.decode('utf-8', errors='ignore')
        except:
            pass
        return output
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        接続情報を取得
        
        Returns:
            Dict[str, Any]: 接続情報
        """
        return {
            "hostname": self.hostname,
            "username": self.username,
            "port": self.port,
            "is_connected": self.is_connected,
            "is_alive": self.is_alive(),
            "auto_sudo_fix": self.auto_sudo_fix,
            "session_recovery": self.session_recovery,
            "sudo_configured": bool(self.sudo_password),
            "heredoc_cleanup": self.heredoc_cleanup
        }
    
    def __enter__(self):
        """コンテキストマネージャー開始"""
        if not self.connect():
            raise ConnectionError("SSH接続に失敗しました")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """コンテキストマネージャー終了"""
        self.disconnect()


# 使用例とテスト用のユーティリティ関数
def example_usage():
    """使用例（ヒアドキュメント対応版）"""
    # ヒアドキュメント対応版の使用方法
    executor = SSHCommandExecutor(
        hostname="your-server.com",
        username="your-username",
        password="your-password",
        sudo_password="your-sudo-password",
        auto_sudo_fix=True,
        session_recovery=True,
        heredoc_cleanup=True,                    # 新機能: ヒアドキュメントクリーンアップ
        default_command_timeout=60.0
    )
    
    try:
        # 接続
        if executor.connect():
            # ヒアドキュメントテスト（マーカー混入なし）
            heredoc_command = """cat > /tmp/test_file.txt << EOF
これはテストファイルです。
複数行のテキストを書き込みます。
SSH_CMD_MARKERが混入しません。
EOF"""
            
            print("=== ヒアドキュメントテスト ===")
            result = executor.execute_command(heredoc_command)
            print(f"Status: {result.status.value}")
            print(f"Heredoc Detected: {result.heredoc_detected}")
            print(f"Files Cleaned: {result.heredoc_files_cleaned}")
            print(f"Output:\n{result.stdout}")
            
            # ファイル内容確認
            verify_result = executor.execute_command("cat /tmp/test_file.txt")
            print("=== ファイル内容確認 ===")
            print(verify_result.stdout)
            
            # sudo + ヒアドキュメントの組み合わせ
            sudo_heredoc_command = """sudo cat > /tmp/sudo_test.txt << EOF
sudoでのヒアドキュメントテスト
マーカー混入なし
EOF"""
            
            print("=== sudo + ヒアドキュメントテスト ===")
            sudo_result = executor.execute_command(sudo_heredoc_command)
            print(f"Status: {sudo_result.status.value}")
            print(f"Auto Fixed: {sudo_result.auto_fixed}")
            print(f"Heredoc Detected: {sudo_result.heredoc_detected}")
            print(f"Files Cleaned: {sudo_result.heredoc_files_cleaned}")
            
            # 複数コマンド実行（ヒアドキュメント含む）
            commands = [
                "echo 'テスト開始'",
                """cat > /tmp/batch_test.txt << EOF
バッチ実行テスト
複数行テキスト
EOF""",
                "cat /tmp/batch_test.txt",
                "rm /tmp/batch_test.txt"
            ]
            
            print("=== バッチ実行テスト ===")
            batch_results = executor.execute_commands(commands)
            
            for i, result in enumerate(batch_results):
                print(f"Command {i+1}: {result.command[:30]}...")
                print(f"Status: {result.status.value}")
                if result.heredoc_detected:
                    print(f"Heredoc Files Cleaned: {result.heredoc_files_cleaned}")
                print(f"Output: {result.stdout}")
                print("---")
        
    finally:
        executor.disconnect()


if __name__ == "__main__":
    # ログ設定
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("SSH Command Executor Library - ヒアドキュメント対応版")
    print("新機能:")
    print("- ヒアドキュメント構文の自動検出")
    print("- マーカー混入問題の完全解決")
    print("- ファイル自動クリーンアップ機能")
    print("- sudo + ヒアドキュメントの組み合わせ対応")
    print("- 既存機能との完全な互換性")
    print("使用例については example_usage() 関数を参照してください")
