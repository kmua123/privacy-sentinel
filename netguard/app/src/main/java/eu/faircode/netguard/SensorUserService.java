package eu.faircode.netguard;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Build;
import android.os.Process;
import android.os.RemoteException;
import android.os.UserHandle;

import androidx.annotation.Keep;
import androidx.annotation.RequiresApi;

/** Runs as the Shizuku shell user and forwards only sensor-start metadata. */
@Keep
@RequiresApi(Build.VERSION_CODES.R)
public final class SensorUserService extends ISensorWatch.Stub {
    static final String WATCH_APPOPS = "android.permission.WATCH_APPOPS";

    private final Context context;
    private final int clientUid;
    private AppOpsManager appOps;
    private AppOpsManager.OnOpActiveChangedListener watcher;
    private ISensorEvent receiver;
    private final android.os.IBinder.DeathRecipient clientDied = this::destroy;

    public SensorUserService(Context context) {
        this.context = context;
        this.clientUid = context.getApplicationInfo().uid;
    }

    @Override
    public synchronized void watch(ISensorEvent listener) throws RemoteException {
        if (Binder.getCallingUid() != clientUid || listener == null)
            throw new SecurityException("Invalid sensor watch caller");

        long identity = Binder.clearCallingIdentity();
        try {
            if (context.checkPermission(WATCH_APPOPS, Process.myPid(), Process.myUid())
                    != PackageManager.PERMISSION_GRANTED)
                throw new SecurityException("Shizuku does not have WATCH_APPOPS");
            if (watcher != null)
                throw new IllegalStateException("Sensor watch already started");

            appOps = context.getSystemService(AppOpsManager.class);
            if (appOps == null)
                throw new IllegalStateException("AppOps service is unavailable");
            listener.asBinder().linkToDeath(clientDied, 0);
            receiver = listener;
            watcher = (operation, uid, packageName, active) -> {
                if (!active || packageName == null || uid < 0
                        || !UserHandle.getUserHandleForUid(uid)
                        .equals(UserHandle.getUserHandleForUid(clientUid)))
                    return;
                try {
                    listener.started(operation, uid, packageName, System.currentTimeMillis());
                } catch (RemoteException ignored) {
                    // The death recipient stops the watcher if the app process exits.
                }
            };
            try {
                appOps.startWatchingActive(new String[]{AppOpsManager.OPSTR_CAMERA,
                        AppOpsManager.OPSTR_RECORD_AUDIO}, Runnable::run, watcher);
            } catch (RuntimeException ex) {
                receiver.asBinder().unlinkToDeath(clientDied, 0);
                receiver = null;
                watcher = null;
                throw ex;
            }
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    @Override
    public synchronized void destroy() {
        long identity = Binder.clearCallingIdentity();
        try {
            if (watcher != null)
                appOps.stopWatchingActive(watcher);
        } finally {
            if (receiver != null)
                receiver.asBinder().unlinkToDeath(clientDied, 0);
            Binder.restoreCallingIdentity(identity);
            // Shizuku runs this class in a separate process owned by the shell user.
            System.exit(0);
        }
    }
}
