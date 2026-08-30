package com.govcraft.garrison;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Key;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import org.jetbrains.annotations.NotNull;

import java.util.function.Consumer;

/** Find Action and Keymap entry points for every command in the chat panel. */
public final class GarrisonActions {
    private static final Key<GarrisonToolWindow> PANEL = Key.create("garrison.toolWindow.panel");

    private GarrisonActions() {}

    static void register(Project project, GarrisonToolWindow panel) {
        project.putUserData(PANEL, panel);
    }

    static void unregister(Project project, GarrisonToolWindow panel) {
        if (project.getUserData(PANEL) == panel) project.putUserData(PANEL, null);
    }

    private static void withPanel(AnActionEvent event, Consumer<GarrisonToolWindow> command) {
        Project project = event.getProject();
        if (project == null) return;
        ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow("Garrison");
        if (toolWindow == null) return;
        toolWindow.activate(() -> {
            GarrisonToolWindow panel = project.getUserData(PANEL);
            if (panel != null) command.accept(panel);
        });
    }

    public static final class Send extends AnAction implements DumbAware {
        @Override public void actionPerformed(@NotNull AnActionEvent event) {
            withPanel(event, GarrisonToolWindow::sendPrompt);
        }
    }

    public static final class Cancel extends AnAction implements DumbAware {
        @Override public void actionPerformed(@NotNull AnActionEvent event) {
            withPanel(event, GarrisonToolWindow::cancelTurn);
        }
    }

    public static final class NewSession extends AnAction implements DumbAware {
        @Override public void actionPerformed(@NotNull AnActionEvent event) {
            withPanel(event, GarrisonToolWindow::newSession);
        }
    }

    public static final class ShowStatus extends AnAction implements DumbAware {
        @Override public void actionPerformed(@NotNull AnActionEvent event) {
            withPanel(event, GarrisonToolWindow::showStatus);
        }
    }
}
