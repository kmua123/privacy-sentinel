package eu.faircode.netguard;

import java.util.EnumSet;

final class TrafficRisk {
    private static final String FOCUS_PACKAGE_NAME = "com.mobiletools.systemhelper";
    private static final long MIN_OUTBOUND_BYTES = 1024L * 1024L;
    private static final long MIN_OUTBOUND_TO_INBOUND_RATIO = 3;

    enum Reason {
        FOCUS_PACKAGE,
        OUTBOUND_HEAVY,
        ACCESSIBILITY_WITH_OUTBOUND,
        NOTIFICATION_ACCESS_WITH_OUTBOUND
    }

    private TrafficRisk() {
    }

    /**
     * Returns review cues for one UID over one sampling window. For shared UIDs,
     * package membership and enabled access do not identify the sender.
     */
    static EnumSet<Reason> reasons(String[] packages, boolean accessibility,
                                   boolean notificationAccess, long rxDelta, long txDelta) {
        EnumSet<Reason> reasons = EnumSet.noneOf(Reason.class);
        if (packages != null) {
            for (String packageName : packages) {
                if (FOCUS_PACKAGE_NAME.equals(packageName)) {
                    reasons.add(Reason.FOCUS_PACKAGE);
                    break;
                }
            }
        }
        if (txDelta <= 0)
            return reasons;

        if (txDelta >= MIN_OUTBOUND_BYTES && rxDelta >= 0
                && rxDelta <= txDelta / MIN_OUTBOUND_TO_INBOUND_RATIO)
            reasons.add(Reason.OUTBOUND_HEAVY);
        if (accessibility)
            reasons.add(Reason.ACCESSIBILITY_WITH_OUTBOUND);
        if (notificationAccess)
            reasons.add(Reason.NOTIFICATION_ACCESS_WITH_OUTBOUND);
        return reasons;
    }
}
