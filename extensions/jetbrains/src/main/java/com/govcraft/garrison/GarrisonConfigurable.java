package com.govcraft.garrison;

import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.options.ConfigurationException;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.util.Objects;

public final class GarrisonConfigurable implements Configurable {
    private JBTextField agentPath;
    private JBTextField socket;
    private JBTextField configPath;
    private JBCheckBox inlineCompletionEnabled;
    private JBTextField inlineCompletionDebounceMs;

    @Override
    public @Nls String getDisplayName() { return "Garrison"; }

    @Override
    public @Nullable JComponent createComponent() {
        var state = GarrisonSettings.getInstance().getState();
        agentPath = new JBTextField(state.agentPath);
        socket = new JBTextField(state.socket);
        configPath = new JBTextField(state.configPath);
        agentPath.setToolTipText("Runs `garrison-agent acp`, a relay to the per-user daemon; starts the daemon if needed.");
        socket.setToolTipText("The daemon's Unix socket; empty uses $XDG_RUNTIME_DIR/garrison-agent.sock.");
        configPath.setToolTipText("Read by the relay for [server] only; never passed to an autostarted daemon.");
        inlineCompletionEnabled = new JBCheckBox("Suggest code at the cursor as you type",
                state.inlineCompletionEnabled);
        inlineCompletionDebounceMs = new JBTextField(Integer.toString(state.inlineCompletionDebounceMs));
        inlineCompletionDebounceMs.setToolTipText("How long typing must pause before the agent is asked. An explicit invocation ignores it.");
        return FormBuilder.createFormBuilder()
                .addLabeledComponent("Agent executable:", agentPath)
                .addLabeledComponent("Daemon socket (optional):", socket)
                .addLabeledComponent("Garrison config (optional):", configPath)
                .addComponent(inlineCompletionEnabled)
                .addLabeledComponent("Inline completion delay (ms):", inlineCompletionDebounceMs)
                .addComponentFillVertically(new JPanel(), 0)
                .getPanel();
    }

    @Override
    public boolean isModified() {
        var state = GarrisonSettings.getInstance().getState();
        return !Objects.equals(agentPath.getText(), state.agentPath)
                || !Objects.equals(socket.getText(), state.socket)
                || !Objects.equals(configPath.getText(), state.configPath)
                || inlineCompletionEnabled.isSelected() != state.inlineCompletionEnabled
                || debounceMsOrNull() == null
                || debounceMsOrNull() != state.inlineCompletionDebounceMs;
    }

    @Override
    public void apply() throws ConfigurationException {
        Integer debounceMs = debounceMsOrNull();
        if (debounceMs == null) {
            throw new ConfigurationException(
                    "Enter a whole number from 0 through 5000 milliseconds.",
                    "Invalid inline completion delay");
        }
        var state = GarrisonSettings.getInstance().getState();
        state.agentPath = agentPath.getText().trim();
        state.socket = socket.getText().trim();
        state.configPath = configPath.getText().trim();
        state.inlineCompletionEnabled = inlineCompletionEnabled.isSelected();
        state.inlineCompletionDebounceMs = debounceMs;
    }

    /**
     * The delay field as a number the provider can use.
     *
     * <p>An invalid value stays visible so {@link #apply()} can identify it to
     * the user instead of silently saving a different value.
     */
    private Integer debounceMsOrNull() {
        try {
            int value = Integer.parseInt(inlineCompletionDebounceMs.getText().trim());
            return value >= 0 && value <= 5000 ? value : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    @Override
    public void reset() {
        var state = GarrisonSettings.getInstance().getState();
        agentPath.setText(state.agentPath);
        socket.setText(state.socket);
        configPath.setText(state.configPath);
        inlineCompletionEnabled.setSelected(state.inlineCompletionEnabled);
        inlineCompletionDebounceMs.setText(Integer.toString(state.inlineCompletionDebounceMs));
    }
}
