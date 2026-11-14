package eu.faircode.netguard;

import android.os.Bundle;

interface ITrafficSnapshotService {
    Bundle readSnapshot() = 0;
    // Shizuku's reserved transaction for shutting down a UserService.
    void destroy() = 16777114;
}
