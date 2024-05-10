# eddsa-api

## Introduction

API plugin to bundle [`net.i2p.crypto:eddsa`](https://central.sonatype.com/artifact/net.i2p.crypto/eddsa).

OpenJDK > 15 provide [native support](https://bugs.openjdk.org/browse/JDK-8190219) for `EdDSA` signatures via the [Java cryptography API](https://docs.oracle.com/pls/topic/lookup?ctx=javase17&id=security_guide_jca), however there are several libraries that are still using older libraries that require this code directly.  
This plugin is seen as an interim so we can ship a single copy of the library whilst consumers migrate away from it.

## Contributing

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)

