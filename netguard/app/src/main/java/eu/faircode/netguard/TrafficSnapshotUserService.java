package eu.faircode.netguard;

import android.content.Context;
import android.os.Binder;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.SparseArray;

import androidx.annotation.Keep;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/** Reads boot-cumulative network counters in a Shizuku shell process. */
@Keep
public final class TrafficSnapshotUserService extends ITrafficSnapshotService.Stub {
    static final String UIDS = "uids";
    static final String RX_BYTES = "rxBytes";
    static final String TX_BYTES = "txBytes";
    static final String ELAPSED_REALTIME = "elapsedRealtime";
    static final String ERROR = "error";

    private static final int MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
    private static final int MAX_UIDS = 10000;
    private static final int TIMEOUT_SECONDS = 6;
    private static final Pattern FIELDS = Pattern.compile("\\s+");
    private static final String[] HEADER = {"uid", "rxBytes", "rxPackets", "txBytes", "txPackets"};

    private final int clientUid;
    private Process running;
    private boolean destroyed;

    public TrafficSnapshotUserService(Context context) {
        clientUid = context.getApplicationInfo().uid;
    }

    @Override
    public Bundle readSnapshot() {
        if (Binder.getCallingUid() != clientUid)
            throw new SecurityException("Invalid traffic snapshot caller");

        final Process process;
        synchronized (this) {
            if (destroyed)
                return error("disconnected");
            if (running != null)
                return error("busy");
            try {
                process = new ProcessBuilder("/system/bin/dumpsys", "-t", "5", "netstats", "--full")
                        .redirectErrorStream(true)
                        .start();
            } catch (IOException ex) {
                return error("failed");
            }
            running = process;
        }

        FutureTask<Bundle> reader = new FutureTask<>(() -> readOutput(process));
        try {
            Thread thread = new Thread(reader, "netstats-reader");
            thread.setDaemon(true);
            thread.start();
            return reader.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException ex) {
            return error("timeout");
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return error("interrupted");
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            return error(cause instanceof SnapshotException ? cause.getMessage() : "failed");
        } finally {
            reader.cancel(true);
            if (process.isAlive())
                process.destroyForcibly();
            synchronized (this) {
                running = null;
            }
        }
    }

    @Override
    public synchronized void destroy() {
        destroyed = true;
        if (running != null && running.isAlive())
            running.destroyForcibly();
        // Only the isolated Shizuku UserService process exits.
        System.exit(0);
    }

    private static Bundle readOutput(Process process) throws IOException, InterruptedException {
        process.getOutputStream().close();
        try (BufferedReader input = new BufferedReader(new InputStreamReader(
                new LimitedInputStream(process.getInputStream()), StandardCharsets.UTF_8))) {
            SparseArray<long[]> counters = new SparseArray<>();
            int sectionIndent = -1;
            boolean hasHeader = false;
            String line;
            while ((line = input.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.contains("DUMP TIMEOUT"))
                    return error("timeout");
                if (trimmed.startsWith("Permission Denial:"))
                    return error("permission_denied");
                if (trimmed.isEmpty())
                    continue;
                if (sectionIndent == -1) {
                    if ("mAppUidStatsMap:".equals(trimmed) || "mAppUidStatsMap::".equals(trimmed))
                        sectionIndent = line.indexOf(trimmed);
                    continue;
                }
                String[] fields = FIELDS.split(trimmed);
                if (!hasHeader) {
                    if (!Arrays.equals(HEADER, fields))
                        return error("unsupported");
                    hasHeader = true;
                    continue;
                }
                if (trimmed.charAt(0) < '0' || trimmed.charAt(0) > '9') {
                    if (line.indexOf(trimmed) <= sectionIndent && trimmed.endsWith(":"))
                        return snapshot(counters);
                    return error("invalid_counters");
                }
                addCounters(counters, fields);
            }
            if (process.waitFor() != 0)
                return error("failed");
            return hasHeader ? snapshot(counters) : error("unsupported");
        }
    }

    private static void addCounters(SparseArray<long[]> counters, String[] fields) throws SnapshotException {
        if (fields.length != HEADER.length)
            throw new SnapshotException("invalid_counters");
        try {
            int uid = Integer.parseInt(fields[0]);
            long rxBytes = Long.parseLong(fields[1]);
            long rxPackets = Long.parseLong(fields[2]);
            long txBytes = Long.parseLong(fields[3]);
            long txPackets = Long.parseLong(fields[4]);
            if (uid < 0 || rxBytes < 0 || rxPackets < 0 || txBytes < 0 || txPackets < 0)
                throw new SnapshotException("invalid_counters");
            if (counters.size() == MAX_UIDS && counters.indexOfKey(uid) < 0)
                throw new SnapshotException("too_large");
            // A concurrent kernel map deletion can cause an entry to be emitted twice.
            counters.put(uid, new long[]{rxBytes, txBytes});
        } catch (NumberFormatException ex) {
            throw new SnapshotException("invalid_counters");
        }
    }

    private static Bundle snapshot(SparseArray<long[]> counters) {
        int size = counters.size();
        int[] uids = new int[size];
        long[] received = new long[size];
        long[] sent = new long[size];
        for (int index = 0; index < size; index++) {
            uids[index] = counters.keyAt(index);
            long[] counts = counters.valueAt(index);
            received[index] = counts[0];
            sent[index] = counts[1];
        }
        Bundle result = new Bundle(4);
        result.putIntArray(UIDS, uids);
        result.putLongArray(RX_BYTES, received);
        result.putLongArray(TX_BYTES, sent);
        result.putLong(ELAPSED_REALTIME, SystemClock.elapsedRealtime());
        return result;
    }

    private static Bundle error(String code) {
        Bundle result = new Bundle(1);
        result.putString(ERROR, code);
        return result;
    }

    private static final class SnapshotException extends IOException {
        SnapshotException(String code) {
            super(code);
        }
    }

    private static final class LimitedInputStream extends FilterInputStream {
        private int remaining = MAX_OUTPUT_BYTES;

        LimitedInputStream(InputStream input) {
            super(input);
        }

        @Override
        public int read() throws IOException {
            if (remaining == 0)
                throw new SnapshotException("too_large");
            int value = in.read();
            if (value != -1)
                remaining--;
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            if (length == 0)
                return 0;
            if (remaining == 0)
                throw new SnapshotException("too_large");
            int count = in.read(bytes, offset, Math.min(length, remaining));
            if (count > 0)
                remaining -= count;
            return count;
        }
    }
}
