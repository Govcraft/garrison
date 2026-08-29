package com.govcraft.garrison;

import com.intellij.openapi.options.Configurable;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.util.Objects;

public final class GarrisonConfigurable implements Configurable {
    private JBTextField agentPath;
    private JBTextField configPath;
    private JBTextField actonConfigPath;

    @Override
    public @Nls String getDisplayName() { return "Garrison"; }

    @Override
    public @Nullable JComponent createComponent() {
        var state = GarrisonSettings.getInstance().getState();
        agentPath = new JBTextField(state.agentPath);
        configPath = new JBTextField(state.configPath);
        actonConfigPath = new JBTextField(state.actonConfigPath);
        return FormBuilder.createFormBuilder()
                .addLabeledComponent("Agent executable:", agentPath)
                .addLabeledComponent("Garrison config (optional):", configPath)
                .addLabeledComponent("acton-ai config (optional):", actonConfigPath)
                .addComponentFillVertically(new JPanel(), 0)
                .getPanel();
    }

    @Override
    public boolean isModified() {
        var state = GarrisonSettings.getInstance().getState();
        return !Objects.equals(agentPath.getText(), state.agentPath)
                || !Objects.equals(configPath.getText(), state.configPath)
                || !Objects.equals(actonConfigPath.getText(), state.actonConfigPath);
    }

    @Override
    public void apply() {
        var state = GarrisonSettings.getInstance().getState();
        state.agentPath = agentPath.getText().trim();
        state.configPath = configPath.getText().trim();
        state.actonConfigPath = actonConfigPath.getText().trim();
    }

    @Override
    public void reset() {
        var state = GarrisonSettings.getInstance().getState();
        agentPath.setText(state.agentPath);
        configPath.setText(state.configPath);
        actonConfigPath.setText(state.actonConfigPath);
    }
}
