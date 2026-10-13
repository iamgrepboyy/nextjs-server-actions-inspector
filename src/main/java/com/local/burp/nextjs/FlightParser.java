package com.local.burp.nextjs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FlightParser {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern FRAME = Pattern.compile("^([0-9a-fA-F]+):(.*)$");
    private static final Pattern ACTION_MARKER = Pattern.compile(
            "\\$ACTION_(?:ID|REF)_([A-Za-z0-9_-]+)", Pattern.CASE_INSENSITIVE);

    private FlightParser() {
    }

    public static List<FlightRecord> parse(String body) {
        List<FlightRecord> records = new ArrayList<>();
        if (body == null || body.isEmpty()) {
            return records;
        }

        for (String line : body.split("\\r?\\n", -1)) {
            Matcher frame = FRAME.matcher(line);
            if (!frame.matches()) {
                continue;
            }

            String payload = frame.group(2);
            String tag = "";
            if (payload.length() > 1 && Character.isUpperCase(payload.charAt(0))
                    && "[{\"$0123456789".indexOf(payload.charAt(1)) >= 0) {
                tag = payload.substring(0, 1);
                payload = payload.substring(1);
            }

            records.add(new FlightRecord(frame.group(1), tag, payload, prettyJson(payload)));
        }
        return records;
    }

    public static List<String> actionIds(String nextActionHeader, String content) {
        Set<String> ids = new LinkedHashSet<>();
        if (nextActionHeader != null && !nextActionHeader.isBlank()) {
            ids.add(nextActionHeader.trim());
        }
        if (content != null) {
            Matcher marker = ACTION_MARKER.matcher(content);
            while (marker.find()) {
                ids.add(marker.group(1));
            }
        }
        return new ArrayList<>(ids);
    }

    public static boolean looksLikeFlight(String content) {
        return !parse(content).isEmpty() || (content != null && ACTION_MARKER.matcher(content).find());
    }

    public static String format(String title, String nextActionHeader, String body) {
        StringBuilder output = new StringBuilder(title).append('\n');
        List<String> ids = actionIds(nextActionHeader, body);
        output.append("Action IDs: ").append(ids.isEmpty() ? "none detected" : String.join(", ", ids))
                .append("\n\n");

        List<FlightRecord> records = parse(body);
        if (records.isEmpty()) {
            output.append("No numbered Flight rows detected. Body follows as captured:\n\n")
                    .append(body == null ? "" : body);
            return output.toString();
        }

        for (FlightRecord record : records) {
            output.append("Chunk ").append(record.id());
            if (!record.tag().isEmpty()) {
                output.append(" [").append(record.tag()).append(']');
            }
            output.append(":\n").append(record.readablePayload()).append("\n\n");
        }
        return output.toString();
    }

    private static String prettyJson(String payload) {
        try {
            JsonNode node = JSON.readTree(payload);
            return node == null ? payload : node.toPrettyString();
        } catch (Exception ignored) {
            return payload;
        }
    }

    public record FlightRecord(String id, String tag, String payload, String readablePayload) {
    }
}