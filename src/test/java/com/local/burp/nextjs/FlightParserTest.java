package com.local.burp.nextjs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class FlightParserTest {
    @Test
    void parsesAndPrettyPrintsJsonFlightRows() {
        List<FlightParser.FlightRecord> records = FlightParser.parse(
                "0:{\"name\":\"demo\",\"ok\":true}\n1:I[\"/app/page\",[\"x\"]]");

        assertEquals(2, records.size());
        assertEquals("0", records.get(0).id());
        assertTrue(records.get(0).readablePayload().contains("\"name\" : \"demo\""));
        assertEquals("I", records.get(1).tag());
    }

    @Test
    void extractsHeaderAndEmbeddedActionReferencesOnce() {
        List<String> ids = FlightParser.actionIds("header-id", "$ACTION_ID_body-id $ACTION_REF_ref-id");

        assertEquals(List.of("header-id", "body-id", "ref-id"), ids);
    }

    @Test
    void recognizesActionFormPayloadWithoutNumberedRows() {
        assertTrue(FlightParser.looksLikeFlight("$ACTION_ID_abc123"));
    }
}