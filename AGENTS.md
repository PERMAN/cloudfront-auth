# AGENTS.md

このドキュメントは、AIエージェントや自動化ツールがこのプロジェクトを扱う際の重要なガイドラインです。

## 重要なルール

### 1. バージョン固定の徹底

**すべての依存関係は固定バージョン（`1.2.3`形式）のみ使用してください。範囲指定（`^`, `~`, `>=`等）は絶対に使用しないでください。**

- package.jsonの依存関係を変更する際は、必ず固定バージョンを指定
- package-lock.jsonから実際のバージョンを確認して使用
- 範囲指定を検出した場合は、即座に固定バージョンに変更

### 2. 承認プロセス

**新しいパッケージをインストールする前に、必ず以下の形式でユーザーに確認を求めてください：**

```
このパッケージ（パッケージ名@1.2.3）をインストールしてよいですか？（y/N）:
```

承認がない場合、インストールをキャンセルしてください。

### 3. 禁止コマンド（通常の運用）

**通常の運用では、以下のコマンドは実行しないでください：**

- `npm install パッケージ名`（バージョン指定なし）
- `npm install`（確認なしの一括インストール）
- `npm update`

**例外**: トラブルシューティング時のみ、ユーザーの明示的な承認を得た上で`npm install`を実行することができます（後述の「トラブルシューティング」セクションを参照）。

### 4. 推奨コマンド

依存関係のインストールには、以下のコマンドを使用してください：

- `npm ci` - package-lock.jsonから正確にインストール（ビルド時）
- `npm install パッケージ名@1.2.3` - バージョン指定でのインストール（承認後）

## プロジェクト構造

```
cloudfront-auth/
├── app/
│   ├── package.json          # すべての依存関係が固定バージョン
│   ├── package-lock.json     # 依存関係のロックファイル
│   ├── .npmrc                # npm設定（save-exact=true, ignore-scripts=true）
│   ├── SECURITY_POLICY.md    # セキュリティポリシー詳細
│   └── src/                  # ソースコード
├── build.sh                  # ビルドスクリプト（npm ciを使用）
└── AGENTS.md                 # このファイル
```

## 依存関係の変更手順

1. **package-lock.jsonから実際のバージョンを確認**
   ```bash
   cd app/
   grep -A 2 '"node_modules/パッケージ名":' package-lock.json
   ```

2. **package.jsonを固定バージョンに更新**
   - 範囲指定（`^`, `~`, `>=`等）を削除
   - 固定バージョン（`1.2.3`形式）に変更

3. **変更後の確認**
   ```bash
   cd app/
   grep -E '[\^~>=<]' package.json
   ```
   このコマンドで範囲指定が残っていないか確認（ビルドスクリプト内の`>=`は除く）

4. **ビルドの確認**
   ```bash
   cd app/
   npm ci
   npm run build
   ```

## セキュリティ対策

このプロジェクトはShai-Hulud 2.0対策を実施しています：

- **save-exact=true**: バージョン範囲指定を防止
- **ignore-scripts=true**: インストール時のスクリプト実行を無効化
- **npm ci**: 再現性の高いインストール
- **固定バージョン**: 予期しない更新を防止

詳細は`app/SECURITY_POLICY.md`を参照してください。

## チェックリスト

依存関係を変更する際は、以下を確認してください：

- [ ] package.jsonのすべての依存関係が固定バージョン（範囲指定なし）になっている
- [ ] package-lock.jsonが存在し、最新の状態である
- [ ] build.shでnpm ciを使用している（npm installではない）
- [ ] ビルドが正常に完了することを確認した
- [ ] 新しいパッケージを追加する場合は、ユーザーの承認を得た

## トラブルシューティング

### package-lock.jsonがpackage.jsonと一致しない

**重要**: この手順は「禁止コマンド」セクションの例外として、トラブルシューティング時のみ承認を得て実行可能です。

package-lock.jsonがpackage.jsonと一致しない場合、以下の手順で再生成できます：

```bash
cd app/
rm -rf node_modules package-lock.json
npm install
```

**実行前の確認事項**:
- package.jsonのすべての依存関係が固定バージョン（範囲指定なし）になっていることを確認
- ユーザーから明示的な承認を得ていること

**注意**: `.npmrc`の`save-exact=true`設定により、package-lock.jsonは固定バージョンで再生成されます。ただし、この操作は通常の運用では避けるべきです。可能な限り`npm ci`を使用してください。

### ignore-scripts=trueでビルドが失敗する

現在使用しているRollupはpostinstallスクリプトが不要なため、この問題は通常発生しません。Rollupは純JavaScript実装のため、`.npmrc`の`ignore-scripts=true`設定のままで正常に動作します。

将来的にpostinstallスクリプトを必要とするパッケージを追加する場合は、環境変数を使用して一時的にスクリプト実行を許可できます：

```bash
cd app/
npm_config_ignore_scripts=false npm ci
```

**重要**: `.npmrc`の`ignore-scripts=true`は変更せず、環境変数で一時的に上書きしてください。これにより、通常の運用では引き続きセキュリティ保護が有効です。

## 参考資料

- [app/SECURITY_POLICY.md](app/SECURITY_POLICY.md) - セキュリティポリシー詳細
- [npm ci documentation](https://docs.npmjs.com/cli/v8/commands/npm-ci)
- [npm security best practices](https://docs.npmjs.com/security-best-practices)

