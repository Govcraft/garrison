package com.govcraft.garrison;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.project.Project;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * The one connection to {@code garrison-agent} for a project.
 *
 * <p>Both the tool window and the inline completion provider talk to the same
 * agent process and the same session. A second connection would mean a second
 * child process, a second session, and a second copy of whatever the agent is
 * holding for this project. It lives in a project service rather than inside
 * the tool window because completions have to work whether or not that window
 * was ever opened.
 *
 * <p>Handlers are installed by whoever wants them — in practice the tool
 * window, when it is created. They are dispatched through stable lambdas held
 * by this service, so a tool window opened <em>after</em> the completion
 * provider already started the agent still receives that agent's events
 * without the connection being torn down and rebuilt.
 */
@Service(Service.Level.PROJECT)
public final class GarrisonConnection implements Disposable {
    /** What a listener is told about frames the agent sent unprompted. */
    public interface Listener {
        void notification(JsonObject frame);

        void agentRequest(JsonElement id, String method, JsonObject params);
    }

    private final Project project;
    private volatile AcpClient client;
    private volatile String sessionId;
    private volatile Listener listener;

    public GarrisonConnection(Project project) {
        this.project = project;
    }

    public static GarrisonConnection getInstance(Project project) {
        return project.getService(GarrisonConnection.class);
    }

    /**
     * Installs the handler for frames the agent sends on its own.
     *
     * <p>Until one is installed, notifications are dropped and any request the
     * agent makes is answered as cancelled — refusing is the only safe reading
     * of "nobody is here to decide".
     */
    public void setListener(Listener listener) {
        this.listener = listener;
    }

    /** Whether a session is already open, without opening one. */
    public boolean hasSession() {
        return sessionId != null;
    }

    /** Connects if needed, returning the live client. */
    public synchronized AcpClient connect() throws Exception {
        if (client != null) return client;
        String basePath = project.getBasePath();
        if (basePath == null) throw new IOException("Open a local project to start Garrison");

        var candidate = new AcpClient(Path.of(basePath), GarrisonSettings.getInstance().getState(),
                this::dispatchNotification, this::dispatchRequest);
        var params = new JsonObject();
        params.addProperty("protocolVersion", 1);
        params.add("clientCapabilities", new JsonObject());
        var info = new JsonObject();
        info.addProperty("name", "garrison-jetbrains");
        info.addProperty("version", "0.1.0");
        params.add("clientInfo", info);
        try {
            candidate.request("initialize", params).get();
        } catch (Exception error) {
            candidate.close();
            throw error;
        }
        client = candidate;
        return client;
    }

    /** Connects and opens a session if needed, returning its identifier. */
    public synchronized String session() throws Exception {
        var active = connect();
        if (sessionId != null) return sessionId;
        var params = new JsonObject();
        params.addProperty("cwd", project.getBasePath());
        params.add("mcpServers", new JsonArray());
        sessionId = active.request("session/new", params).get().get("sessionId").getAsString();
        return sessionId;
    }

    /** Sends a request, connecting first if needed. */
    public CompletableFuture<JsonObject> request(String method, JsonObject params) throws Exception {
        return connect().request(method, params);
    }

    /** Sends a notification. Does nothing when not connected. */
    public void notify(String method, JsonObject params) throws IOException {
        var active = client;
        if (active != null) active.notify(method, params);
    }

    /** Answers a request the agent made. Does nothing when not connected. */
    public void respond(JsonElement id, JsonObject result) {
        var active = client;
        if (active != null) active.respond(id, result);
    }

    /**
     * Forgets the current session so the next caller opens a fresh one.
     *
     * <p>The connection is kept: the agent process is fine, it is the
     * conversation that is being restarted.
     */
    public void resetSession() {
        sessionId = null;
    }

    private void dispatchNotification(JsonObject frame) {
        var current = listener;
        if (current != null) current.notification(frame);
    }

    private void dispatchRequest(JsonElement id, String method, JsonObject params) {
        var current = listener;
        if (current != null) {
            current.agentRequest(id, method, params);
            return;
        }
        var outcome = new JsonObject();
        outcome.addProperty("outcome", "cancelled");
        var result = new JsonObject();
        result.add("outcome", outcome);
        respond(id, result);
    }

    @Override
    public synchronized void dispose() {
        if (client != null) client.close();
        client = null;
        sessionId = null;
        listener = null;
    }
}
