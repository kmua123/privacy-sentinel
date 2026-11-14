package eu.faircode.netguard;

import eu.faircode.netguard.ISensorEvent;

interface ISensorWatch {
    void watch(ISensorEvent listener) = 0;
    // Shizuku's reserved transaction for shutting down a UserService.
    void destroy() = 16777114;
}
