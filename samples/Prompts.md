# Claude Sonent 4 ＋ mcp-ssh-serverで実際に使用したプロンプト

## Knowledgeインストール

### プロンプト

```
添付したknowledgeインストール時の注意事項に関するドキュメントを参照しながら、
ssh-command-serverで、SSHサーバプロファイルtest-serverでログインし、knowledgeをインストールしてください。
javaのインストール、tomcat 9のインストール、jaxbライブラリの追加、まで完了しています。
knowledgeのデプロイから先をお願いします。
```

### コメント

これで、以下を順にやってくれました。

* java がインストールされているか確認
* Tomcat 9 がインストールされているか確認
* jaxbライブラリが追加されているか確認
* Tomcatの停止
* knowledgeのダウンロード
* knowledgeのをwebappsにコピー
* Tomcatの開始
* 接続確認

実は、以下のプロンプトで１回動かしていて、長さの上限で、jaxbライブラリのインストールで終了してしまっていました。
その後上記プロンプトで追加のデプロイをしてもらって、インストールが完了しています。

```
添付したknowledgeインストール時の注意事項に関するドキュメントを参照しながら、
ssh-command-serverで、SSHサーバプロファイルtest-serverでログインし、knowledgeをインストールしてください。
```

この時渡したファイルは、このフォルダにある「Knowledgeインストール時の注意事項.txt」です。

