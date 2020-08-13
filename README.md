# YubiKey-Discriminator
[![Go Report Card](https://goreportcard.com/badge/github.com/task4233/YubiKey-Discriminator)](https://goreportcard.com/report/github.com/task4233/YubiKey-Discriminator)
![GitHub Actions](https://github.com/task4233/YubiKey-Discriminator/workflows/Static%20check%20with%20PR%20and%20Add%20comment%20each%20error/badge.svg)

Serial Numberを持たないYubiKeyでも、登録したYubiKeyのみで所有者を特定できる機能を追加したデモサーバ。
[koesie10 / webauthn-demo](https://github.com/koesie10/webauthn-demo)をベースに作成。

## Usage

```
go run .
```

10011ポートで動きます([localhost:10011](http://localhost:10011))。


## License

MIT.
