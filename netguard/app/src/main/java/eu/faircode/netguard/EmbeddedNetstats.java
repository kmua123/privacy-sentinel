package eu.faircode.netguard;

import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Strict parser for Android's per-UID boot-cumulative traffic snapshot. */
final class EmbeddedNetstats {
    private static final String[] HEADER = {"uid", "rxBytes", "rxPackets", "txBytes", "txPackets"};
    private static final int MAX_LINES = 250_000;
    private static final int MAX_CHARACTERS = 16 * 1024 * 1024;

    static JSONObject collect() throws Exception {
        Process process = new ProcessBuilder("/system/bin/dumpsys", "-t", "5", "netstats", "--full")
                .redirectErrorStream(true).start();
        process.getOutputStream().close();
        FutureTask<JSONObject> task = new FutureTask<>(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8))) {
                JSONObject result = parse(reader, SystemClock.elapsedRealtime());
                if (process.waitFor() != 0)
                    throw new IOException("netstats_failed");
                return result;
            }
        });
        Thread worker = new Thread(task, "embedded-netstats");
        worker.setDaemon(true);
        worker.start();
        try {
            return task.get(7, TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            throw new IOException("netstats_timeout", timeout);
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof IOException)
                throw (IOException) cause;
            throw new IOException("netstats_failed", cause);
        } finally {
            task.cancel(true);
            if (process.isAlive())
                process.destroyForcibly();
        }
    }

    static JSONObject parse(BufferedReader reader, long elapsed) throws Exception {
        Map<Integer, long[]> totals = new TreeMap<>();
        int sectionIndent = -1;
        boolean hasHeader = false;
        boolean sectionEnded = false;
        int lines = 0;
        int characters = 0;
        String line;
        while ((line = reader.readLine()) != null) {
            if (++lines > MAX_LINES || (characters += line.length()) > MAX_CHARACTERS)
                throw new IOException("netstats_too_large");
            String trimmed = line.trim();
            if (trimmed.contains("DUMP TIMEOUT"))
                throw new IOException("netstats_timeout");
            if (trimmed.startsWith("Permission Denial:"))
                throw new IOException("netstats_permission_denied");
            if (trimmed.isEmpty())
                continue;
            // Keep draining stdout after the UID section. Waiting for dumpsys before
            // reading its remaining --full output can deadlock on a full pipe.
            if (sectionEnded)
                continue;
            if (sectionIndent == -1) {
                if (trimmed.equals("mAppUidStatsMap:") || trimmed.equals("mAppUidStatsMap::"))
                    sectionIndent = line.indexOf(trimmed);
                continue;
            }
            String[] fields = trimmed.split("\\s+");
            if (!hasHeader) {
                if (!Arrays.equals(HEADER, fields))
                    throw new IOException("netstats_unsupported");
                hasHeader = true;
                continue;
            }
            if (!Character.isDigit(trimmed.charAt(0))) {
                if (line.indexOf(trimmed) <= sectionIndent && trimmed.matches("[A-Za-z][^:]*:.*")) {
                    sectionEnded = true;
                    continue;
                }
                throw new IOException("netstats_invalid_counters");
            }
            if (fields.length != HEADER.length)
                throw new IOException("netstats_invalid_counters");
            int uid;
            long received;
            long receivedPackets;
            long sent;
            long sentPackets;
            try {
                uid = Integer.parseInt(fields[0]);
                received = Long.parseLong(fields[1]);
                receivedPackets = Long.parseLong(fields[2]);
                sent = Long.parseLong(fields[3]);
                sentPackets = Long.parseLong(fields[4]);
            } catch (NumberFormatException invalid) {
                throw new IOException("netstats_invalid_counters", invalid);
            }
            if (uid < 0 || received < 0 || receivedPackets < 0 || sent < 0 || sentPackets < 0)
                throw new IOException("netstats_invalid_counters");
            if (totals.size() >= 10_000 && !totals.containsKey(uid))
                throw new IOException("netstats_too_large");
            // A concurrently deleted map entry can be emitted twice. Keep its last value.
            totals.put(uid, new long[]{received, sent});
        }
        if (!hasHeader)
            throw new IOException("netstats_unsupported");
        JSONArray uids = new JSONArray();
        JSONArray received = new JSONArray();
        JSONArray sent = new JSONArray();
        for (Map.Entry<Integer, long[]> row : totals.entrySet()) {
            uids.put(row.getKey());
            received.put(row.getValue()[0]);
            sent.put(row.getValue()[1]);
        }
        return new JSONObject().put("uids", uids).put("rxBytes", received).put("txBytes", sent)
                .put("elapsedRealtime", elapsed);
    }
}
