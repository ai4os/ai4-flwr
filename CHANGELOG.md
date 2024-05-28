# Changelog

## [1.0.0](https://github.com/ai4os/ai4-flwr/compare/0.2.0...v1.0.0) (2024-05-28)


### ⚠ BREAKING CHANGES

* include initial Vault implementation
* allow to provide more than one Bearer token

### Features

* Add method for renewing Vault token ([0b21647](https://github.com/ai4os/ai4-flwr/commit/0b216472b55ad25613b50bc9503d70ac5cb608d1))
* add release-please files ([8fbfadc](https://github.com/ai4os/ai4-flwr/commit/8fbfadcb78f74fdd889100a20904c872cac825df))
* add release-please Github Action ([37c2c06](https://github.com/ai4os/ai4-flwr/commit/37c2c060a677335f5abb252a6c4c62ef3156bfa7))
* allow to provide more than one Bearer token ([7532309](https://github.com/ai4os/ai4-flwr/commit/75323098027cb9e2a6621948249d4d315e51b15f))
* automatically renew Vault tokens via coroutines ([c351027](https://github.com/ai4os/ai4-flwr/commit/c3510276cda3f68796424b8eadbfe70dee88ee9a))
* implement reading token from file and reload via SIGUSR1 ([2147daa](https://github.com/ai4os/ai4-flwr/commit/2147daa4ec17ec3e2792f06a7c0b575c290bdeeb))
* Improve Vault code and classes ([e3a2fc8](https://github.com/ai4os/ai4-flwr/commit/e3a2fc878d2625bc2f1ebd13688f56245982f5d4))
* include initial Vault implementation ([42a8a00](https://github.com/ai4os/ai4-flwr/commit/42a8a00182f5b39d70e63ec850dd2b8b9923d0cc))


### Bug Fixes

* Change Flower dep to use AI4EOSC fork ([0a4f476](https://github.com/ai4os/ai4-flwr/commit/0a4f476671c8c77431fdcf04fe881c1921616b1f))
* change release type version to Python ([de8425c](https://github.com/ai4os/ai4-flwr/commit/de8425c4e897c1d201fb48adb2386d4ba6e9f40a))
* continuation should be stream_stream, not unary_unary ([d2c06d3](https://github.com/ai4os/ai4-flwr/commit/d2c06d3b1cfe838df39c9b9da98f54a0502153ec))
* make class more generic, and rename to OIDC ([f6985ab](https://github.com/ai4os/ai4-flwr/commit/f6985abfe0041622f9014e6b6c45bcb3f2638eb2))
* use x-authorization as header ([4ff4f8d](https://github.com/ai4os/ai4-flwr/commit/4ff4f8d9613c7b5eb9d7a691d1647a28396b8c9f))


### Documentation

* add bearer token example ([87665af](https://github.com/ai4os/ai4-flwr/commit/87665af14ee7bbce10b4b48e1a75a7a163366449))
