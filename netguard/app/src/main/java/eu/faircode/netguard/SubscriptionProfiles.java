package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Immutable cache generations; the preference index is the only publication point. */
final class SubscriptionProfiles {
    static final String INDEX = "subscription_profiles_v1";
    static final String ACTIVE = "active_subscription_id";
    static final String MIGRATED = "subscription_profiles_migrated";
    static final String LOCAL_CACHE = "local_profile_cache";
    static final String LOCAL_SELECTED = "local_profile_selected";
    static final String LOCAL_AVAILABLE = "local_profile_available";
    static final String LOCAL_ID = "00000000-0000-0000-0000-000000000000";
    static final int MAX_PROFILES = 32;
    static final int MAX_URL = 8192;
    private static final int MAX_INDEX = 512 * 1024;
    private static final int MAX_CACHE = 2 * 1024 * 1024;
    private static final String UUID_PATTERN = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private final File directory;

    static final class Entry {
        final String id;
        final String name;
        final String url;
        final String cache;
        final String selected;

        Entry(String id, String name, String url, String cache, String selected) {
            this.id = id;
            this.name = name;
            this.url = url;
            this.cache = cache;
            this.selected = selected;
        }

        Entry renamed(String name) { return new Entry(id, name, url, cache, selected); }
        Entry cached(String cache, String selected) { return new Entry(id, name, url, cache, selected); }
        Entry selected(String selected) { return cached(cache, selected); }
    }

    SubscriptionProfiles(File files) {
        directory = new File(files, "subscription-cache");
    }

    static String newId() { return UUID.randomUUID().toString(); }

    static String checkedName(String name) throws IOException {
        String value = name == null ? "" : name.trim();
        if (value.isEmpty() || value.length() > 80 || value.matches("(?s).*[\\p{Cntrl}].*"))
            throw new IOException("订阅名称需要 1 到 80 个可见字符");
        return value;
    }

    static void checkedId(String id) throws IOException {
        if (id == null || !id.matches(UUID_PATTERN))
            throw new IOException("订阅标识无效，请重新选择");
    }

    static List<Entry> parse(String encoded) throws IOException {
        if (encoded == null || encoded.length() > MAX_INDEX)
            throw new IOException("订阅列表内容无效");
        try {
            JSONArray values = new JSONArray(encoded);
            if (values.length() > MAX_PROFILES)
                throw new IOException("最多保存 32 个订阅");
            List<Entry> result = new ArrayList<>();
            Set<String> ids = new HashSet<>();
            Set<String> urls = new HashSet<>();
            for (int i = 0; i < values.length(); i++) {
                JSONObject value = values.getJSONObject(i);
                String id = string(value, "id");
                String name = checkedName(string(value, "name"));
                String url = string(value, "url");
                String cache = string(value, "cache");
                String selected = string(value, "selected");
                checkedId(id);
                if (LOCAL_ID.equals(id) || !ids.add(id) || !urls.add(url)
                        || url.isEmpty() || url.length() > MAX_URL || selected.length() > 512)
                    throw new IOException("订阅列表包含重复或无效项目");
                if (!cache.isEmpty())
                    checkedId(cache);
                result.add(new Entry(id, name, url, cache, selected));
            }
            return result;
        } catch (JSONException malformed) {
            throw new IOException("订阅列表格式无效，原有文件未改动", malformed);
        }
    }

    static String encode(List<Entry> entries) throws IOException {
        if (entries.size() > MAX_PROFILES)
            throw new IOException("最多保存 32 个订阅");
        JSONArray result = new JSONArray();
        try {
            for (Entry entry : entries)
                result.put(new JSONObject().put("id", entry.id).put("name", entry.name)
                        .put("url", entry.url).put("cache", entry.cache).put("selected", entry.selected));
        } catch (JSONException impossible) {
            throw new IOException("无法保存订阅列表", impossible);
        }
        String encoded = result.toString();
        // Apply exactly the same invariants before the atomic preference commit.
        parse(encoded);
        return encoded;
    }

    private static String string(JSONObject value, String key) throws JSONException {
        Object item = value.get(key);
        if (!(item instanceof String))
            throw new JSONException("Invalid field type");
        return (String) item;
    }

    static Entry byId(List<Entry> entries, String id) {
        for (Entry entry : entries)
            if (entry.id.equals(id))
                return entry;
        return null;
    }

    static Entry byUrl(List<Entry> entries, String url) {
        for (Entry entry : entries)
            if (entry.url.equals(url))
                return entry;
        return null;
    }

    static void replace(List<Entry> entries, Entry replacement) {
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).id.equals(replacement.id)) {
                entries.set(i, replacement);
                return;
            }
        }
        entries.add(replacement);
    }

    boolean hasCache(String id, String generation) throws IOException {
        return !generation.isEmpty() && file(id, generation).isFile();
    }

    String writeCache(String id, String yaml) throws IOException {
        checkedId(id);
        byte[] bytes = yaml.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0 || bytes.length > MAX_CACHE)
            throw new IOException("节点配置超过 2 MiB 缓存上限");
        if (!directory.isDirectory() && !directory.mkdirs())
            throw new IOException("无法创建订阅缓存目录");
        String generation = newId();
        File destination = file(id, generation);
        boolean finished = false;
        try (FileOutputStream output = new FileOutputStream(destination)) {
            output.write(bytes);
            output.getFD().sync();
            finished = true;
        } finally {
            if (!finished)
                destination.delete();
        }
        return generation;
    }

    String readCache(String id, String generation) throws IOException {
        File source = file(id, generation);
        try (FileInputStream input = new FileInputStream(source)) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (result.size() + count > MAX_CACHE)
                    throw new IOException("订阅缓存超过 2 MiB 上限");
                result.write(buffer, 0, count);
            }
            return new String(result.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    void discardCache(String id, String generation) {
        if (generation == null || generation.isEmpty())
            return;
        try { file(id, generation).delete(); }
        catch (IOException ignored) { }
    }

    private File file(String id, String generation) throws IOException {
        checkedId(id);
        checkedId(generation);
        File file = new File(directory, id + "-" + generation + ".yaml");
        if (!file.getCanonicalFile().getParentFile().equals(directory.getCanonicalFile()))
            throw new IOException("订阅缓存路径无效");
        return file;
    }

    static String chooseNode(String previous, boolean hadCache, List<String> names) throws IOException {
        if (names.isEmpty())
            throw new IOException("订阅中没有可用节点");
        if (previous != null && (names.contains(previous) || hadCache && previous.isEmpty()))
            return previous;
        return names.get(0);
    }
}
