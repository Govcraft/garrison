package com.govcraft.garrison;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.intellij.openapi.diagnostic.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

final class AcpClient implements AutoCloseable {
    interface AgentRequestHandler { void handle(JsonElement id, String method, JsonObject params); }

    private static final Logger LOG = Logger.getInstance(AcpClient.class);
    private final AtomicLong nextId = new AtomicLong(1);
    private final Map<Long, CompletableFuture<JsonObject>> pending = new ConcurrentHashMap<>();
    private final Consumer<JsonObject> notificationHandler;
    private final AgentRequestHandler requestHandler;
    private final Process process;
    private final BufferedWriter writer;
    private final ExecutorService readers = Executors.newFixedThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "garrison-acp");
        thread.setDaemon(true);
        return thread;
    });

    AcpClient(Path cwd, GarrisonSettings.State settings, Consumer<JsonObject> notificationHandler,
              AgentRequestHandler requestHandler) throws IOException {
        this.notificationHandler = notificationHandler;
        this.requestHandler = requestHandler;
        // `acp` is a relay to the per-user daemon's socket; the flags only say
        // where that socket is. The daemon's configuration governs the session.
        String executable = settings.agentPath.isBlank() ? "garrison-agent" : settings.agentPath;
        var command = new java.util.ArrayList<>(List.of(executable, "acp"));
        if (!settings.socket.isBlank()) command.addAll(List.of("--socket", settings.socket));
        if (!settings.configPath.isBlank()) command.addAll(List.of("--config", settings.configPath));
        process = new ProcessBuilder(command).directory(cwd.toFile()).start();
        writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
        readers.submit(this::readStdout);
        readers.submit(this::readStderr);
    }

    CompletableFuture<JsonObject> request(String method, JsonObject params) {
        long id = nextId.getAndIncrement();
        var future = new CompletableFuture<JsonObject>();
        pending.put(id, future);
        var frame = new JsonObject();
        frame.addProperty("jsonrpc", "2.0");
        frame.addProperty("id", id);
        frame.addProperty("method", method);
        frame.add("params", params);
        try { write(frame); }
        catch (IOException error) { pending.remove(id); future.completeExceptionally(error); }
        return future;
    }

    void notify(String method, JsonObject params) throws IOException {
        var frame = new JsonObject();
        frame.addProperty("jsonrpc", "2.0");
        frame.addProperty("method", method);
        frame.add("params", params);
        write(frame);
    }

    void respond(JsonElement id, JsonObject result) {
        var frame = new JsonObject();
        frame.addProperty("jsonrpc", "2.0");
        frame.add("id", id);
        frame.add("result", result);
        try { write(frame); } catch (IOException error) { LOG.warn("Could not answer ACP request", error); }
    }

    private synchronized void write(JsonObject frame) throws IOException {
        if (!process.isAlive()) throw new IOException("garrison-agent is not running");
        writer.write(frame.toString());
        writer.newLine();
        writer.flush();
    }

    private void readStdout() {
        try (var input = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) receive(line);
            failAll(new IOException("garrison-agent closed the ACP connection"));
        } catch (Exception error) { failAll(error); }
    }

    private void readStderr() {
        try (var input = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) LOG.info(line);
        } catch (IOException error) { LOG.debug(error); }
    }

    private void receive(String line) {
        try {
            var frame = JsonParser.parseString(line).getAsJsonObject();
            if (frame.has("method")) {
                String method = frame.get("method").getAsString();
                var params = frame.has("params") ? frame.getAsJsonObject("params") : new JsonObject();
                if (frame.has("id")) requestHandler.handle(frame.get("id"), method, params);
                else notificationHandler.accept(frame);
                return;
            }
            if (!frame.has("id")) return;
            long id = frame.get("id").getAsLong();
            var future = pending.remove(id);
            if (future == null) return;
            if (frame.has("error")) {
                var error = frame.getAsJsonObject("error");
                String detail = error.has("data") ? ": " + error.get("data") : "";
                future.completeExceptionally(new IOException(error.get("message").getAsString() + detail));
            } else {
                var result = frame.get("result");
                future.complete(result != null && result.isJsonObject() ? result.getAsJsonObject() : new JsonObject());
            }
        } catch (Exception error) { LOG.warn("Ignoring malformed ACP frame: " + line, error); }
    }

    private void failAll(Throwable error) {
        pending.values().forEach(future -> future.completeExceptionally(error));
        pending.clear();
    }

    @Override
    public void close() {
        failAll(new CancellationException("Garrison connection closed"));
        process.destroy();
        readers.shutdownNow();
    }
}
