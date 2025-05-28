# 修正版SSH実行ライブラリをインポート
try:
    from debug_ssh_command_executor import SSHCommandExecutor, CommandResult, CommandStatus
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

def main():
    session = SSHCommandExecutor('192.168.4.4', 'tester', 'tester', None, 22, 30.0, 300.0, 'tester', True, True, True)
    session.connect()
    cmd = "export LANG=ja_JP.UTF-8\ncat > /tmp/here.txt << 'EOF'\nヒアドキュメントテスト開始\n==================\n\nこのファイルは複数行のテストデータです。\n\n日本語テスト:\n- ひらがな: あいうえお\n- カタカナ: アイウエオ  \n- 漢字: 日本語文字化けテスト\n\n特殊文字テスト:\n- 変数記号: $HOME, $USER\n- バッククォート: `date`\n- 引用符: \"double quote\", 'single quote'\n- その他記号: !@#$%^&*()\n\n複数行構造テスト:\n  インデント行1\n    インデント行2\n      より深いインデント\n\n最終行です。\nEOF\n"
    cmd = "cat > /tmp/here.txt << 'EOF'\nAAA\nBBB\nEOF\n"
    cmd = "export LANG=ja_JP.UTF-8 ; cat > /tmp/here.txt << 'EOF'\nAAA\nヒアドキュメントテスト開始\nBBB\nEOF\n"
    cmd = "export LANG=ja_JP.UTF-8 ; cat > /tmp/here.txt << 'EOF'\nAAA\nこんにちは\nBBB\nEOF\n"
    cmd = "export LANG=ja_JP.UTF-8 ; cat > /tmp/here.txt << 'EOF'\nAAA\nZZZ\nBBB\nEOF\n"
    cmd = "export LANG=ja_JP.UTF-8\ncat > /tmp/here.txt << EOF\n$LANG\nAAA\nZZZ\nBBB\nEOF\n"
    cmd = "export LANG=ja_JP.UTF-8 && cat > /tmp/here.txt << EOF\n$LANG\nAAA\nZZZ\nBBB\nEOF\n"
    cmd = "cat > /tmp/here.txt << EOF\n$LANG\nAAA\nZZZ\nBBB\nEOF\n"

    cmd = "export LANG=ja_JP.UTF-8\ncat > /tmp/here.txt << 'EOF'\nxヒアドキュメントテスト開始\n==================\n\nxこのファイルは複数行のテストデータです。\n\nx日本語テスト:\n- ひらがな: あいうえお\n- カタカナ: アイウエオ  \n- 漢字: 日本語文字化けテスト\n\nx特殊文字テスト:\n- 変数記号: $HOME, $USER\n- バッククォート: `date`\n- 引用符: \"double quote\", 'single quote'\n- その他記号: !@#$%^&*()\n\nx複数行構造テスト:\n  インデント行1\n    インデント行2\n      より深いインデント\n\n最終行です。\nEOF\n"

    # import pdb; pdb.set_trace()
    session.execute_command(cmd, sudo_password="tester")

if __name__ == "__main__":
    main()
