# セキュリティポリシー

## Shai-Hulud 2.0対策

このプロジェクトは、npmサプライチェーン攻撃（Shai-Hulud 2.0）に対する対策を実施しています。

## バージョン管理ポリシー

### 基本方針

1. **バージョン固定の徹底**: すべての依存関係は固定バージョン（`1.2.3`形式）のみ使用します。範囲指定（`^`, `~`, `>=`等）は絶対に使用しません。

2. **承認プロセス**: 新しいパッケージをインストールする前に、必ずバージョンを指定し、承認を得てからインストールします。

3. **禁止コマンド**: 以下のコマンドは絶対に実行しません：
   - `npm install パッケージ名`（バージョン指定なし）
   - `npm install`（確認なしの一括インストール）
   - `npm update`

## .npmrc設定

プロジェクトの`.npmrc`ファイルに以下の設定が含まれています：

```
audit=true
fund=false
package-lock=true
registry=https://registry.npmjs.org/
save-exact=true
ignore-scripts=true
```

### 設定の説明

- `audit=true`: セキュリティ監査を有効化
- `fund=false`: 資金提供メッセージを無効化
- `package-lock=true`: package-lock.jsonの生成を強制
- `registry=https://registry.npmjs.org/`: 公式npmレジストリを使用
- `save-exact=true`: バージョンを正確に保存（範囲指定を防止）
- `ignore-scripts=true`: インストール時のスクリプト実行を無効化（サプライチェーン攻撃対策）

## ビルドプロセス

### npm ciの使用

ビルドスクリプト（`../build.sh`）では、`npm install`の代わりに`npm ci`を使用します。

`npm ci`の利点：
- package-lock.jsonから正確に依存関係をインストール
- より高速で信頼性が高い
- 本番環境での再現性が高い

### Rollupの使用

このプロジェクトでは、Rollup 4.22.4以降（CVE-2024-47068修正済み）をバンドルツールとして使用しています。Rollupは純JavaScript実装のため、postinstallスクリプトが不要であり、`.npmrc`の`ignore-scripts=true`設定のままで正常に動作します。これにより、セキュリティ保護を維持しながら、ビルドプロセスを実行できます。

## 依存関係の更新手順

1. package-lock.jsonから実際のバージョンを確認
2. package.jsonの依存関係を固定バージョンに更新
3. 変更をコミット前にレビュー
4. ビルドが正常に動作することを確認

## トラブルシューティング

### ignore-scripts=trueでビルドが失敗する場合

現在使用しているRollupはpostinstallスクリプトが不要なため、この問題は発生しません。ただし、将来的にpostinstallスクリプトを必要とするパッケージを追加する場合は、環境変数を使用して一時的にスクリプト実行を許可できます：

```bash
npm_config_ignore_scripts=false npm ci
```

**注意**: `.npmrc`の`ignore-scripts=true`は変更せず、環境変数で一時的に上書きしてください。

### npm ciでエラーが発生する場合

package-lock.jsonがpackage.jsonと一致していない可能性があります。以下の手順で再生成してください：

```bash
rm -rf node_modules package-lock.json
npm install
```

**注意**: この操作は承認が必要です。

## チェックリスト

依存関係を変更する際は、以下を確認してください：

- [ ] package.jsonのすべての依存関係が固定バージョン（範囲指定なし）になっている
- [ ] package-lock.jsonが存在し、最新の状態である
- [ ] build.shでnpm ciを使用している（npm installではない）
- [ ] ビルドが正常に完了することを確認した

## 参考資料

- [npm ci documentation](https://docs.npmjs.com/cli/v8/commands/npm-ci)
- [npm security best practices](https://docs.npmjs.com/security-best-practices)


