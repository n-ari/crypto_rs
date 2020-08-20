# crypto_rs

## これは何

暗号プリミティブ(暗号化関数、復号関数、ハッシュ関数、有限体、……)を Rust 言語で実装するリポジトリです。

CTF の Crypto 問題を解くため、暗号研究においてプロトタイプを実装するためなどに使用することを想定しています。

このリポジトリのクレート及びソースコードをプロダクトに使用することは推奨されません。
このリポジトリはあくまで実験用であり、例えばサイドチャネル攻撃等を考慮していません。

## 実装状況

- [x] AES (Rijndael) (鍵長 128 bit, 192 bit, 256 bit; 暗号化のみ)

## License

MIT

