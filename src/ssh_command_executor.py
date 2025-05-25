import paramiko
import threading
import time
import uuid
import re
import logging
from typing import Optional, Tuple, Dict, Any
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


class SSHCommandExecutor:
    """
    SSH経由でコマンドを実行するためのライブラリ - sudo問題修正版
    
    特徴:
    - セッション維持
    - マーカー方式による確実なレスポンス終了検出
    - ステータスコード取得
    - タイムアウト対応
    - スレッドセーフ
    - sudo問題自動修正
    - セッション復旧機能
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
                 session_recovery: bool = True):
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
        コマンドを実行（sudo問題修正版）
        
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
        複数のコマンドを順次実行（sudo問題修正版）
        
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
            "sudo_configured": bool(self.sudo_password)
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
    """使用例（sudo問題修正版）"""
    # 基本的な使用方法
    executor = SSHCommandExecutor(
        hostname="your-server.com",
        username="your-username",
        password="your-password",
        sudo_password="your-sudo-password",  # 新しいパラメータ
        auto_sudo_fix=True,                  # sudo自動修正
        session_recovery=True,               # セッション復旧
        default_command_timeout=60.0
    )
    
    try:
        # 接続
        if executor.connect():
            # sudo問題が自動修正される
            result = executor.execute_command("sudo ls /root")
            print(f"Exit Code: {result.exit_code}")
            print(f"Output:\n{result.stdout}")
            print(f"Auto Fixed: {result.auto_fixed}")
            print(f"Session Recovered: {result.session_recovered}")
            
            # 複数コマンド実行（sudo含む）
            commands = [
                "pwd",
                "sudo ls /root",    # 自動修正される
                "echo 'Hello World'"
            ]
            results = executor.execute_commands(commands, sudo_password="password")
            
            for i, result in enumerate(results):
                print(f"Command {i+1}: {result.command}")
                print(f"Status: {result.status.value}")
                print(f"Output: {result.stdout}")
                if result.auto_fixed:
                    print(f"Original: {result.original_command}")
                print("---")
        
    finally:
        executor.disconnect()
    
    # コンテキストマネージャーとしての使用
    try:
        with SSHCommandExecutor(
            hostname="your-server.com",
            username="your-username",
            password="your-password",
            sudo_password="your-sudo-password",
            auto_sudo_fix=True,
            session_recovery=True
        ) as ssh:
            result = ssh.execute_command("sudo systemctl status nginx")
            print(result.stdout)
    except ConnectionError as e:
        print(f"接続エラー: {e}")


if __name__ == "__main__":
    # ログ設定
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("SSH Command Executor Library - sudo問題修正版")
    print("新機能:")
    print("- sudo問題の自動検出と修正")
    print("- セッション復旧機能")
    print("- sudo用パスワード個別指定")
    print("- 強化されたエラーハンドリング")
    print("使用例については example_usage() 関数を参照してください")
