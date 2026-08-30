package com.govcraft.garrison;

import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.ContentFactory;
import org.jetbrains.annotations.NotNull;

public final class GarrisonToolWindowFactory implements ToolWindowFactory, DumbAware {
    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        var panel = new GarrisonToolWindow(project);
        GarrisonActions.register(project, panel);
        var content = ContentFactory.getInstance().createContent(panel.component(), "", false);
        content.setPreferredFocusableComponent(panel.preferredFocusComponent());
        content.setDisposer(panel);
        toolWindow.getContentManager().addContent(content);
    }
}
