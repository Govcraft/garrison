package com.govcraft.garrison;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.*;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.accessibility.AccessibleAnnouncerUtil;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.*;

final class GarrisonToolWindow implements Disposable, GarrisonConnection.Listener {
    private final Project project;
    private final GarrisonConnection connection;
    private final JPanel root = new JPanel(new BorderLayout());
    private final JTextPane transcript = new JTextPane();
    private final JBTextArea input = new JBTextArea(4, 20);
    private final JButton send = new JButton("Send");
    private final JButton cancel = new JButton("Cancel");
    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "garrison-client");
        thread.setDaemon(true);
        return thread;
    });
    private final Map<String, JsonElement> pendingApprovals = new ConcurrentHashMap<>();
    private volatile boolean busy;

    GarrisonToolWindow(Project project) {
        this.project = project;
        this.connection = GarrisonConnection.getInstance(project);
        this.connection.setListener(this);
        transcript.setEditable(false);
        transcript.setContentType("text/plain");
        var scroll = new JBScrollPane(transcript);
        scroll.setBorder(JBUI.Borders.empty());

        var buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        var fresh = new JButton("New");
        var status = new JButton("Status");
        cancel.setVisible(false);
        buttons.add(fresh);
        buttons.add(status);
        buttons.add(cancel);
        buttons.add(send);

        var composer = new JPanel(new BorderLayout(0, 6));
        composer.setBorder(JBUI.Borders.empty(8));
        composer.add(new JBScrollPane(input), BorderLayout.CENTER);
        composer.add(buttons, BorderLayout.SOUTH);
        root.add(scroll, BorderLayout.CENTER);
        root.add(composer, BorderLayout.SOUTH);

        send.addActionListener(event -> sendPrompt());
        cancel.addActionListener(event -> cancelTurn());
        fresh.addActionListener(event -> newSession());
        status.addActionListener(event -> showStatus());
        input.getInputMap().put(KeyStroke.getKeyStroke("ctrl ENTER"), "send");
        input.getActionMap().put("send", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { sendPrompt(); }
        });
    }

    JComponent component() { return root; }

    private void sendPrompt() {
        String text = input.getText().trim();
        if (text.isEmpty() || busy) return;
        input.setText("");
        append("You\n" + text + "\n\n", true);
        announce("Garrison is responding.", false);
        setBusy(true);
        worker.submit(() -> {
            try {
                String id = connection.session();
                var content = new JsonObject();
                content.addProperty("type", "text");
                content.addProperty("text", text);
                var prompt = new JsonArray();
                prompt.add(content);
                var params = new JsonObject();
                params.addProperty("sessionId", id);
                params.add("prompt", prompt);
                connection.request("session/prompt", params).get();
                append("\n", false);
                announce("Garrison response complete.", false);
            } catch (Exception error) { report(error); }
            finally { setBusy(false); }
        });
    }

    @Override
    public void notification(JsonObject frame) {
        if (!"session/update".equals(frame.get("method").getAsString())) return;
        var update = frame.getAsJsonObject("params").getAsJsonObject("update");
        String kind = update.get("sessionUpdate").getAsString();
        if ("agent_message_chunk".equals(kind)) {
            append(update.getAsJsonObject("content").get("text").getAsString(), false);
        } else if ("tool_call".equals(kind)) {
            String title = update.get("title").getAsString();
            String status = value(update, "status", "in progress");
            append("\n[" + title + " · " + status + "]\n", false);
            announce("Tool " + title + ": " + status + ".", false);
        } else if ("tool_call_update".equals(kind)) {
            String status = value(update, "status", "updated");
            append("[Tool " + status + "]\n", false);
            announce("Tool " + status + ".", false);
        }
    }

    @Override
    public void agentRequest(JsonElement id, String method, JsonObject params) {
        if (!"session/request_permission".equals(method)) {
            respondCancelled(id);
            return;
        }
        var call = params.getAsJsonObject("toolCall");
        String toolId = value(call, "toolCallId", id.toString());
        String title = value(call, "title", toolId);
        pendingApprovals.put(toolId, id);
        ApplicationManager.getApplication().invokeLater(() -> {
            String detail = call.has("rawInput") ? "\n\nArguments:\n" + call.get("rawInput") : "";
            String[] labels = {"Allow once", "Always allow", "Reject"};
            int choice = Messages.showDialog(project,
                    "Garrison requests permission to run " + title + detail,
                    "Garrison Approval", labels, 2, Messages.getWarningIcon());
            if (pendingApprovals.remove(toolId) == null) return;
            if (choice == 0) respondSelected(id, "allow_once");
            else if (choice == 1) respondSelected(id, "allow_always");
            else respondSelected(id, "reject_once");
        });
    }

    private void cancelTurn() {
        if (!busy || !connection.hasSession()) return;
        var params = new JsonObject();
        try { params.addProperty("sessionId", connection.session()); }
        catch (Exception error) { report(error); return; }
        try { connection.notify("session/cancel", params); } catch (IOException error) { report(error); }
        pendingApprovals.values().forEach(this::respondCancelled);
        pendingApprovals.clear();
    }

    private void newSession() {
        cancelTurn();
        connection.resetSession();
        ApplicationManager.getApplication().invokeLater(() -> transcript.setText(""));
    }

    private void showStatus() {
        worker.submit(() -> {
            try {
                var status = connection.request("_garrison/status", new JsonObject()).get();
                ApplicationManager.getApplication().invokeLater(() ->
                        Messages.showInfoMessage(project, status.toString(), "Garrison Governance Status"));
            } catch (Exception error) { report(error); }
        });
    }

    private void respondSelected(JsonElement id, String optionId) {
        var outcome = new JsonObject();
        outcome.addProperty("outcome", "selected");
        outcome.addProperty("optionId", optionId);
        var result = new JsonObject();
        result.add("outcome", outcome);
        connection.respond(id, result);
    }

    private void respondCancelled(JsonElement id) {
        var outcome = new JsonObject();
        outcome.addProperty("outcome", "cancelled");
        var result = new JsonObject();
        result.add("outcome", outcome);
        connection.respond(id, result);
    }

    private void append(String text, boolean user) {
        ApplicationManager.getApplication().invokeLater(() -> {
            var attributes = new SimpleAttributeSet();
            if (user) StyleConstants.setBold(attributes, true);
            else StyleConstants.setForeground(attributes, JBColor.foreground());
            try {
                var document = transcript.getStyledDocument();
                document.insertString(document.getLength(), text, attributes);
                transcript.setCaretPosition(document.getLength());
            } catch (BadLocationException ignored) {}
        });
    }

    private void setBusy(boolean value) {
        busy = value;
        ApplicationManager.getApplication().invokeLater(() -> {
            send.setEnabled(!value);
            input.setEnabled(!value);
            cancel.setVisible(value);
        });
    }

    private void announce(String message, boolean interrupt) {
        ApplicationManager.getApplication().invokeLater(() ->
                AccessibleAnnouncerUtil.announce(transcript, message, interrupt));
    }

    private void report(Throwable error) {
        Throwable cause = error instanceof ExecutionException && error.getCause() != null ? error.getCause() : error;
        String message = cause.getMessage();
        announce("Garrison error: " + (message == null || message.isBlank() ? "The operation failed." : message), true);
        ApplicationManager.getApplication().invokeLater(() ->
                Messages.showErrorDialog(project, message, "Garrison"));
    }

    private static String value(JsonObject object, String name, String fallback) {
        return object.has(name) ? object.get(name).getAsString() : fallback;
    }

    @Override
    public void dispose() {
        cancelTurn();
        // The connection belongs to the project service, not to this window:
        // closing it here would kill the agent that inline completion is still
        // using after the tool window is closed.
        connection.setListener(null);
        worker.shutdownNow();
    }
}
