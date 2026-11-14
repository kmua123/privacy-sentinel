package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import java.util.Collection;
import java.util.Objects;
import java.util.TreeSet;

/** Worker-owned recovery state; physical-link ordering must not cause reconnect loops. */
final class NetworkHandoffState {
    private String applied;

    boolean needsRecovery(String current) {
        // Initial startup is owned by onStartCommand, not an asynchronous callback.
        return applied != null && !applied.equals(current);
    }

    void applied(String signature) {
        applied = Objects.requireNonNull(signature);
    }

    static String fingerprint(String identity, String interfaceName, int mtu,
                              Collection<String> addresses, Collection<String> dns,
                              Collection<String> routes) {
        return identity + "|" + interfaceName + "|" + mtu + "|"
                + canonical(addresses) + "|" + canonical(dns) + "|" + canonical(routes);
    }

    private static String canonical(Collection<String> values) {
        // Android can reorder or repeat LinkProperties without changing routing.
        return String.join("\n", new TreeSet<>(values));
    }
}
