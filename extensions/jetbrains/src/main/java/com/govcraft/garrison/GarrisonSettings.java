package com.govcraft.garrison;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import org.jetbrains.annotations.NotNull;

@State(name = "GarrisonSettings", storages = @Storage("garrison.xml"))
public final class GarrisonSettings implements PersistentStateComponent<GarrisonSettings.State> {
    public static final class State {
        public String agentPath = "garrison-agent";
        public String configPath = "";
        public String actonConfigPath = "";
    }

    private State state = new State();

    public static GarrisonSettings getInstance() {
        return ApplicationManager.getApplication().getService(GarrisonSettings.class);
    }

    @Override
    public @NotNull State getState() { return state; }

    @Override
    public void loadState(@NotNull State state) { this.state = state; }
}
