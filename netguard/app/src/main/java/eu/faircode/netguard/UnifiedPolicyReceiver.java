package eu.faircode.netguard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class UnifiedPolicyReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (NetworkApproval.ACTION_TEMPORARY_EXPIRY.equals(intent.getAction()))
            NetworkApproval.get(context).expireTemporary();
    }
}
