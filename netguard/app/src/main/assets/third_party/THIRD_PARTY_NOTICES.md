# Third-party notices and source provenance

This is an independent derivative of NetGuard and Mihomo. Original copyright
headers are retained in the corresponding source trees. The project is distributed
under GPL-3.0; component-specific permissive/MPL/LGPL terms remain applicable.
This notice does not replace the actual component license texts.

## Principal components

| Component | Pinned version/source | License and corresponding source |
| --- | --- | --- |
| NetGuard | 166df969c3cedd7023c13613d9816c185702c6c9 | GPL-3.0; original work by M. Bokhorst; modified complete source and C/JNI build instructions are in netguard/. Upstream: https://github.com/M66B/NetGuard/tree/166df969c3cedd7023c13613d9816c185702c6c9 |
| Mihomo | v1.19.33 / 3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8 | GPL-3.0; modified complete source is in guard-core/mihomo/. Upstream: https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8 |
| zerotier-go | v0.0.0-20260813124750-13fa6f45da5f | MPL-2.0; LICENSE and NOTICE retain ZeroTier Inc. translation/source attribution. Exact module source and hashes are listed in the manifest. |
| LibADB Android | 3.1.1 | COPYING offers GPL-3.0-or-later OR Apache-2.0; additional file-specific BSD/MIT notices are retained. |
| spake2-android | 2.2.1 / 7615ddd680b990e14513ebb66eac4cb0dbf82464 | LGPL-3.0; corresponding source: https://github.com/MuntashirAkon/spake2-java/tree/7615ddd680b990e14513ebb66eac4cb0dbf82464 |
| spake2-c | 0d15933e5ba3e662cb01245a7ac0dc9fca3eac31 | LGPL-3.0; native JNI submodule source: https://github.com/MuntashirAkon/spake2-c/tree/0d15933e5ba3e662cb01245a7ac0dc9fca3eac31 |
| Conscrypt | 2.5.3 / fd209de6167201e4f3bca5b99c6db9f08d1843c6 | Apache-2.0; bundled third-party/BoringSSL attribution is included in its full NOTICE. |
| SnakeYAML | 2.7 | Apache-2.0; source tag: https://codeberg.org/snakeyaml/snakeyaml/src/tag/snakeyaml-2.7 |
| Glide and its support modules | 4.14.2 | Full upstream BSD/Apache/MIT and other third-party notices are included. |
| Bouncy Castle | bcprov-jdk15to18 1.81 | Bouncy Castle permissive licence; full r1rv81 text is included. |
| AndroidX, Kotlin, JetBrains annotations/coroutines, Guava listenablefuture | Resolved versions in manifest.json | Apache-2.0; each exact Maven coordinate and source POM URL is recorded. |
| Go runtime | go1.27.4 | Go BSD-style LICENSE is included. |
| Meta rules data | Fixed source, hashes and licence in netguard/app/src/main/assets/rules/ | Retain the rules source-manifest and GPL licence provided with the APK. |

## Go module notices

The go/ directory contains license, NOTICE, PATENTS and author documents copied
from the exact module cache versions linked into the 0.2.2 native library. The
same dependency versions are pinned by guard-core/go.mod and go.sum for the
public build. The manifest records the canonical Go module source ZIP, original
relative document path and SHA256 for every copied document. It contains no
private build-directory paths. Any later dependency update must update this index.

### chacha v0.1.5 upstream licence repair

The v0.1.5 tag (07294f500ca8384015f6cc21311de7b6f093607d) omitted a root LICENSE.
Upstream then added an MIT LICENSE at commit
7b981d42c3baca5a004e7b0ecfb9b67ee20e583a, identifying Andreas Auernhammer and
MetaCubex. GitHub's comparison of those exact commits contains one commit and
one added file, LICENSE; all program source is unchanged. This bundle includes
that upstream-issued text and a small provenance record, rather than inventing
an authorisation or silently labelling a missing licence.

Comparison: https://github.com/MetaCubeX/chacha/compare/07294f500ca8384015f6cc21311de7b6f093607d...7b981d42c3baca5a004e7b0ecfb9b67ee20e583a

## Source and replacement

Complete modified application/core sources accompany this repository and each
source release. Third-party modules can be retrieved at the pinned source URLs
in the manifest; Go modules are also integrity-pinned by go.sum. No release
signing private key is included. You may modify/rebuild the app, replace its
third-party libraries and sign your modified APK with your own key; Android
requires uninstalling an existing differently signed installation before such
a build can be installed under the same application ID.

License and NOTICE documents are also shipped inside the APK at assets/third_party
and can be viewed through the public build's "隐私说明与开源许可" page.
