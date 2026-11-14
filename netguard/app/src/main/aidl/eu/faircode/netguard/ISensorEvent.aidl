package eu.faircode.netguard;

oneway interface ISensorEvent {
    void started(String operation, int uid, String packageName, long timeMillis);
}
