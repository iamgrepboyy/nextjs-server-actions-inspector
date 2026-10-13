package com.local.burp.nextjs;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;

public class NextActionInspector implements BurpExtension, HttpHandler, ContextMenuItemsProvider {
    private static final int MAX_OBSERVATIONS = 500;
    private static final String DEFAULT_IDENTITY_HEADERS =
            "Cookie, Authorization, X-CSRF-Token, X-XSRF-Token";
    private static final Set<String> BLOCKED_IDENTITY_HEADERS = Set.of(
            "host", "content-length", "transfer-encoding", "connection", "next-action");

    private MontoyaApi api;
    private final Map<Integer, Observation> observationsByMessage = new ConcurrentHashMap<>();
    private final List<Observation> observations = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, HttpRequest> roles = new LinkedHashMap<>();
    private final ObservationTableModel observationModel = new ObservationTableModel();
    private final RoleTableModel roleModel = new RoleTableModel();
    private final ResultTableModel resultModel = new ResultTableModel();
    private final JTable observationTable = new JTable(observationModel);
    private final JTable roleTable = new JTable(roleModel);
    private final JTable resultTable = new JTable(resultModel);
    private final JTextArea targetDetails = readOnlyArea();
    private final JTextArea resultDetails = readOnlyArea();
    private final JLabel statusLabel = new JLabel("Waiting for Next.js Server Action traffic.");
    private final JTextField identityHeaders = new JTextField(DEFAULT_IDENTITY_HEADERS, 32);
    private final JCheckBox confirmStateChanges = new JCheckBox(
            "I confirm replay may execute a state-changing action");
    private final JButton replayButton = new JButton("Replay against selected roles");
    private HttpRequest targetRequest;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
        api.extension().setName("Next.js Server Actions Inspector");
        buildUi();
        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.userInterface().registerHttpRequestEditorProvider(new RequestEditorProvider());
        api.userInterface().registerHttpResponseEditorProvider(new ResponseEditorProvider());
        api.userInterface().registerSuiteTab("Next.js Actions", panel);
        api.logging().logToOutput("Next.js Server Actions Inspector loaded");
    }

    private JPanel panel;

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            List<String> ids = FlightParser.actionIds(
                    request.headerValue("Next-Action"), request.bodyToString());
            int chunks = FlightParser.parse(request.bodyToString()).size();
            if (request.hasHeader("Next-Action") || !ids.isEmpty() || chunks > 0) {
                Observation observation = new Observation(
                        request.messageId(), request.toolSource().toString(), request.url(),
                        request.headerValue("Next-Action"), ids, chunks);
                observationsByMessage.put(request.messageId(), observation);
                synchronized (observations) {
                    observations.add(0, observation);
                    while (observations.size() > MAX_OBSERVATIONS) {
                        Observation removed = observations.remove(observations.size() - 1);
                        observationsByMessage.remove(removed.messageId);
                    }
                }
                SwingUtilities.invokeLater(this::refreshObservations);
            }
        } catch (Exception error) {
            api.logging().logToError("Could not inspect HTTP request: " + error.getMessage());
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            HttpRequest request = response.initiatingRequest();
            String body = response.bodyToString();
            List<FlightParser.FlightRecord> chunks = FlightParser.parse(body);
            List<String> ids = FlightParser.actionIds(
                    request.headerValue("Next-Action"), request.bodyToString());
            ids = mergeIds(ids, FlightParser.actionIds(null, body));
            Observation observation = observationsByMessage.get(response.messageId());

            if (observation == null && (FlightParser.looksLikeFlight(body)
                    || isFlightContentType(response.headerValue("Content-Type")))) {
                observation = new Observation(response.messageId(), response.toolSource().toString(),
                        request.url(), request.headerValue("Next-Action"), ids, chunks.size());
                observationsByMessage.put(response.messageId(), observation);
                synchronized (observations) {
                    observations.add(0, observation);
                    while (observations.size() > MAX_OBSERVATIONS) {
                        Observation removed = observations.remove(observations.size() - 1);
                        observationsByMessage.remove(removed.messageId);
                    }
                }
            }

            if (observation != null) {
                observation.status = Short.toString(response.statusCode());
                observation.flightChunks = chunks.size();
                observation.actionIds = ids;
                SwingUtilities.invokeLater(this::refreshObservations);
            }
        } catch (Exception error) {
            api.logging().logToError("Could not inspect HTTP response: " + error.getMessage());
        }
        return ResponseReceivedAction.continueWith(response);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected.isEmpty()) {
            return Collections.emptyList();
        }

        HttpRequestResponse message = selected.get(0);
        JMenuItem targetItem = new JMenuItem("Load as Server Action replay target");
        targetItem.addActionListener(ignored -> loadTarget(message.request()));
        JMenuItem roleItem = new JMenuItem("Capture request headers as a role");
        roleItem.addActionListener(ignored -> captureRole(message.request()));
        return List.of(targetItem, roleItem);
    }

    private void buildUi() {
        panel = new JPanel(new BorderLayout(6, 6));
        observationTable.setAutoCreateRowSorter(true);
        roleTable.setAutoCreateRowSorter(true);
        roleTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.getSelectionModel().addListSelectionListener(this::showSelectedResult);

        JPanel observationsPanel = new JPanel(new BorderLayout());
        observationsPanel.add(new JLabel("Observed action and Flight traffic"), BorderLayout.NORTH);
        observationsPanel.add(new JScrollPane(observationTable), BorderLayout.CENTER);

        JPanel rolesPanel = new JPanel(new BorderLayout(4, 4));
        rolesPanel.add(new JLabel("Captured roles (identity headers kept in memory only)"),
                BorderLayout.NORTH);
        rolesPanel.add(new JScrollPane(roleTable), BorderLayout.CENTER);

        JPanel targetPanel = new JPanel(new BorderLayout(4, 4));
        targetPanel.add(new JLabel("Replay target"), BorderLayout.NORTH);
        targetPanel.add(new JScrollPane(targetDetails), BorderLayout.CENTER);

        JPanel replayControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        replayControls.add(new JLabel("Identity headers:"));
        replayControls.add(identityHeaders);
        replayControls.add(confirmStateChanges);
        replayControls.add(replayButton);
        replayButton.setEnabled(false);
        confirmStateChanges.addActionListener(event -> updateReplayAvailability());
        replayButton.addActionListener(event -> replaySelectedRoles());

        JPanel resultsPanel = new JPanel(new BorderLayout(4, 4));
        resultsPanel.add(new JLabel("Cross-role responses"), BorderLayout.NORTH);
        resultsPanel.add(new JScrollPane(resultTable), BorderLayout.CENTER);
        resultsPanel.add(new JScrollPane(resultDetails), BorderLayout.SOUTH);

        JSplitPane roleTargetSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                rolesPanel, targetPanel);
        roleTargetSplit.setResizeWeight(0.5);
        JSplitPane lowerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                roleTargetSplit, resultsPanel);
        lowerSplit.setResizeWeight(0.58);
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                observationsPanel, lowerSplit);
        mainSplit.setResizeWeight(0.42);
        panel.add(mainSplit, BorderLayout.CENTER);

        JPanel footer = new JPanel(new BorderLayout());
        footer.add(replayControls, BorderLayout.NORTH);
        footer.add(statusLabel, BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);
        api.userInterface().applyThemeToComponent(panel);
    }

    private void loadTarget(HttpRequest request) {
        if (!request.hasHeader("Next-Action") && FlightParser.actionIds(null, request.bodyToString()).isEmpty()) {
            JOptionPane.showMessageDialog(panel,
                    "The selected request has no Next-Action header or recognized action marker.",
                    "Not a Server Action request", JOptionPane.WARNING_MESSAGE);
            return;
        }
        targetRequest = request;
        targetDetails.setText("URL: " + request.url() + "\nMethod: " + request.method()
                + "\nNext-Action: " + valueOrNone(request.headerValue("Next-Action"))
                + "\nAction IDs: " + String.join(", ", FlightParser.actionIds(
                        request.headerValue("Next-Action"), request.bodyToString()))
                + "\n\n" + FlightParser.format("Request Flight body",
                        request.headerValue("Next-Action"), request.bodyToString()));
        resultModel.setRows(Collections.emptyList());
        resultDetails.setText("");
        statusLabel.setText("Replay target loaded. Capture role requests, then select one or more roles.");
        updateReplayAvailability();
    }

    private void captureRole(HttpRequest request) {
        String name = JOptionPane.showInputDialog(panel, "Role label:", "Capture role",
                JOptionPane.QUESTION_MESSAGE);
        if (name == null || name.trim().isEmpty()) {
            return;
        }
        roles.put(name.trim(), request);
        refreshRoles();
        statusLabel.setText("Captured role '" + name.trim() + "' in memory for this Burp session.");
    }

    private void replaySelectedRoles() {
        if (targetRequest == null || !confirmStateChanges.isSelected()) {
            return;
        }
        if (!targetRequest.isInScope()) {
            statusLabel.setText("Replay blocked: the target request is outside Burp scope.");
            return;
        }

        List<Role> selectedRoles = selectedRoles();
        if (selectedRoles.isEmpty()) {
            statusLabel.setText("Select at least one captured role.");
            return;
        }
        int answer = JOptionPane.showConfirmDialog(panel,
                "Send this Server Action once for each selected role? The action may change server state.",
                "Confirm Server Action replay", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.YES_OPTION) {
            return;
        }

        HttpRequest replayTarget = targetRequest;
        List<String> headerNames = parseIdentityHeaders(identityHeaders.getText());
        if (headerNames.isEmpty()) {
            statusLabel.setText("Add at least one valid identity header name.");
            return;
        }

        replayButton.setEnabled(false);
        resultModel.setRows(Collections.emptyList());
        resultDetails.setText("");
        statusLabel.setText("Replaying action sequentially across " + selectedRoles.size() + " role(s)...");

        new SwingWorker<List<ReplayResult>, Void>() {
            @Override
            protected List<ReplayResult> doInBackground() {
                List<ReplayResult> results = new ArrayList<>();
                for (Role role : selectedRoles) {
                    long started = System.nanoTime();
                    try {
                        HttpRequest replay = applyRoleHeaders(replayTarget, role.request, headerNames);
                        HttpRequestResponse exchange = api.http().sendRequest(replay);
                        HttpResponse response = exchange == null ? null : exchange.response();
                        long elapsed = (System.nanoTime() - started) / 1_000_000;
                        results.add(ReplayResult.from(role.name, response, elapsed));
                    } catch (Exception error) {
                        results.add(ReplayResult.failure(role.name, error.getMessage(),
                                (System.nanoTime() - started) / 1_000_000));
                    }
                }
                return results;
            }

            @Override
            protected void done() {
                replayButton.setEnabled(true);
                try {
                    List<ReplayResult> results = get();
                    resultModel.setRows(results);
                    statusLabel.setText("Completed " + results.size()
                            + " role replay(s). Compare HTTP status and response fingerprints.");
                } catch (Exception error) {
                    statusLabel.setText("Replay failed: " + error.getMessage());
                }
                updateReplayAvailability();
            }
        }.execute();
    }

    private HttpRequest applyRoleHeaders(HttpRequest target, HttpRequest role,
            List<String> headerNames) {
        HttpRequest replay = target;
        for (String name : headerNames) {
            replay = replay.withRemovedHeader(name);
            String value = role.headerValue(name);
            if (value != null) {
                replay = replay.withHeader(name, value);
            }
        }
        return replay;
    }

    private List<String> parseIdentityHeaders(String value) {
        Set<String> names = new LinkedHashSet<>();
        for (String candidate : value.split(",")) {
            String name = candidate.trim();
            if (name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
                    && !BLOCKED_IDENTITY_HEADERS.contains(name.toLowerCase())) {
                names.add(name);
            }
        }
        return new ArrayList<>(names);
    }

    private List<Role> selectedRoles() {
        int[] selectedRows = roleTable.getSelectedRows();
        List<Role> result = new ArrayList<>();
        for (int selectedRow : selectedRows) {
            String name = roleModel.roleAt(roleTable.convertRowIndexToModel(selectedRow));
            HttpRequest request = roles.get(name);
            if (request != null) {
                result.add(new Role(name, request));
            }
        }
        return result;
    }

    private void updateReplayAvailability() {
        replayButton.setEnabled(targetRequest != null && confirmStateChanges.isSelected());
    }

    private void refreshObservations() {
        synchronized (observations) {
            observationModel.setRows(new ArrayList<>(observations));
        }
    }

    private void refreshRoles() {
        roleModel.setRows(new ArrayList<>(roles.keySet()));
    }

    private void showSelectedResult(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        int viewRow = resultTable.getSelectedRow();
        if (viewRow < 0) {
            resultDetails.setText("");
            return;
        }
        ReplayResult result = resultModel.resultAt(resultTable.convertRowIndexToModel(viewRow));
        resultDetails.setText(result == null ? "" : result.details);
    }

    private static List<String> mergeIds(List<String> first, List<String> second) {
        Set<String> merged = new LinkedHashSet<>(first);
        merged.addAll(second);
        return new ArrayList<>(merged);
    }

    private static boolean isFlightContentType(String contentType) {
        return contentType != null && (contentType.toLowerCase().contains("text/x-component")
                || contentType.toLowerCase().contains("application/x-component"));
    }

    private static String valueOrNone(String value) {
        return value == null || value.isBlank() ? "none" : value;
    }

    private static JTextArea readOnlyArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(false);
        area.setTabSize(4);
        return area;
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte item : digest) {
                hex.append(String.format("%02x", item & 0xff));
            }
            return hex.toString();
        } catch (Exception ignored) {
            return "unavailable";
        }
    }

    private final class RequestEditorProvider implements HttpRequestEditorProvider {
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context) {
            return new RequestFlightEditor();
        }
    }

    private final class RequestFlightEditor implements ExtensionProvidedHttpRequestEditor {
        private final JTextArea text = readOnlyArea();
        private HttpRequestResponse current;

        @Override
        public String caption() {
            return "Next.js Flight";
        }

        @Override
        public Component uiComponent() {
            return new JScrollPane(text);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (requestResponse == null || requestResponse.request() == null) {
                return false;
            }
            HttpRequest request = requestResponse.request();
            return request.hasHeader("Next-Action") || FlightParser.looksLikeFlight(request.bodyToString());
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse;
            if (requestResponse == null || requestResponse.request() == null) {
                text.setText("");
                return;
            }
            HttpRequest request = requestResponse.request();
            text.setText(FlightParser.format("Request Flight body",
                    request.headerValue("Next-Action"), request.bodyToString()));
            text.setCaretPosition(0);
        }

        @Override
        public HttpRequest getRequest() {
            return current == null ? HttpRequest.httpRequest() : current.request();
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public Selection selectedData() {
            return null;
        }
    }

    private final class ResponseEditorProvider implements HttpResponseEditorProvider {
        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
            return new ResponseFlightEditor();
        }
    }

    private final class ResponseFlightEditor implements ExtensionProvidedHttpResponseEditor {
        private final JTextArea text = readOnlyArea();
        private HttpRequestResponse current;

        @Override
        public String caption() {
            return "Next.js Flight";
        }

        @Override
        public Component uiComponent() {
            return new JScrollPane(text);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (requestResponse == null || requestResponse.response() == null) {
                return false;
            }
            HttpResponse response = requestResponse.response();
            return FlightParser.looksLikeFlight(response.bodyToString())
                    || isFlightContentType(response.headerValue("Content-Type"));
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse;
            if (requestResponse == null || requestResponse.response() == null) {
                text.setText("");
                return;
            }
            HttpResponse response = requestResponse.response();
            text.setText(FlightParser.format("Response Flight body", null, response.bodyToString()));
            text.setCaretPosition(0);
        }

        @Override
        public HttpResponse getResponse() {
            return current == null || current.response() == null
                    ? HttpResponse.httpResponse() : current.response();
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public Selection selectedData() {
            return null;
        }
    }

    private static final class Observation {
        private final int messageId;
        private final String time;
        private final String tool;
        private final String url;
        private final String nextAction;
        private volatile List<String> actionIds;
        private volatile int flightChunks;
        private volatile String status = "Pending";

        private Observation(int messageId, String tool, String url, String nextAction,
                List<String> actionIds, int flightChunks) {
            this.messageId = messageId;
            this.time = java.time.LocalTime.now().withNano(0).toString();
            this.tool = tool;
            this.url = url;
            this.nextAction = nextAction == null ? "" : nextAction;
            this.actionIds = actionIds;
            this.flightChunks = flightChunks;
        }
    }

    private record Role(String name, HttpRequest request) {
    }

    private static final class ReplayResult {
        private final String role;
        private final String status;
        private final long elapsedMs;
        private final String fingerprint;
        private final String details;

        private ReplayResult(String role, String status, long elapsedMs, String fingerprint,
                String details) {
            this.role = role;
            this.status = status;
            this.elapsedMs = elapsedMs;
            this.fingerprint = fingerprint;
            this.details = details;
        }

        private static ReplayResult from(String role, HttpResponse response, long elapsedMs) {
            if (response == null) {
                return failure(role, "No HTTP response was received.", elapsedMs);
            }
            String body = response.bodyToString();
            String fingerprint = sha256(body);
            String details = "HTTP " + response.statusCode() + "\nSHA-256: " + fingerprint
                    + "\n\n" + FlightParser.format("Response body", null, body);
            if (body.length() > 12000) {
                details = details.substring(0, Math.min(details.length(), 12000))
                        + "\n\n[Response display truncated at 12,000 characters.]";
            }
            return new ReplayResult(role, Short.toString(response.statusCode()), elapsedMs,
                    fingerprint, details);
        }

        private static ReplayResult failure(String role, String message, long elapsedMs) {
            String detail = message == null ? "Request failed." : message;
            return new ReplayResult(role, "Error", elapsedMs, "unavailable", detail);
        }
    }

    private static final class ObservationTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "Tool", "URL", "Next-Action", "Action IDs",
                "Flight chunks", "HTTP"};
        private List<Observation> rows = new ArrayList<>();

        private void setRows(List<Observation> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Observation row = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> row.time;
                case 1 -> row.tool;
                case 2 -> row.url;
                case 3 -> row.nextAction;
                case 4 -> String.join(", ", row.actionIds);
                case 5 -> row.flightChunks;
                default -> row.status;
            };
        }
    }

    private static final class RoleTableModel extends AbstractTableModel {
        private List<String> rows = new ArrayList<>();

        private void setRows(List<String> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        private String roleAt(int row) {
            return rows.get(row);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public String getColumnName(int column) {
            return "Role";
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return rows.get(rowIndex);
        }
    }

    private static final class ResultTableModel extends AbstractTableModel {
        private final String[] columns = {"Role", "HTTP", "Time (ms)", "Body SHA-256"};
        private List<ReplayResult> rows = new ArrayList<>();

        private void setRows(List<ReplayResult> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        private ReplayResult resultAt(int row) {
            return rows.get(row);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ReplayResult row = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> row.role;
                case 1 -> row.status;
                case 2 -> row.elapsedMs;
                default -> row.fingerprint;
            };
        }
    }
}