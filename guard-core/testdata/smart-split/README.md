These fixtures were rendered by the Android project's actual
`ClashProfile.coreYaml()` implementation through the Java host check harness.
The split fixture deliberately uses a node name containing `#` and `&` to test
that the native DNS parser receives the stable local proxy alias correctly.

The MRS files are exact copies of `netguard/app/src/main/assets/rules`, not
manually constructed miniature rule lists. Their upstream license, provenance
and checksums are retained in `rules/`. The integration test also compares these
fixtures against the APK assets when the sibling Android source is present.

The SOCKS endpoint is loopback-only test data. Tests parse configuration, load
local MRS providers and perform actual native rule matching. They never call
Start/PrepareIdentity, dial a node or perform DNS queries.
