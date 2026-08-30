# Accessibility and support

Garrison offers the same governed agent through VS Code, JetBrains IDEs and a
terminal. Choose the surface that works best with your assistive technology;
all three connect to the same per-user daemon, policy, sessions and audit trail.

## Accessible paths

### VS Code

The Garrison sidebar uses VS Code webview controls, visible focus, headings and
live status announcements. Tool approvals use a native VS Code modal whose
default action is rejection. VS Code keyboard navigation, zoom, high-contrast
themes and supported screen readers apply to the Garrison view. Inline
completion is optional and can be disabled with **Garrison: Toggle Inline
Completion**. In the composer, Enter sends and Shift+Enter inserts a newline;
Tab and Shift+Tab follow the webview's control order. New session, cancel,
governance status and inline-completion toggle are also available from the VS
Code Command Palette.

### JetBrains IDEs

The Garrison tool window uses native Swing controls, labels and focus order.
Tool approvals use a native IDE dialog whose default action keeps the
transcript or rejects the requested action. JetBrains keyboard navigation,
font scaling, high-contrast themes and supported screen readers apply to the
tool window. Inline completion can be disabled under **Settings | Tools |
Garrison**. Ctrl+Enter sends from the multiline composer. Send, cancel, new
session and governance status are also exposed through **Find Action** and the
IDE keymap, where users can assign preferred shortcuts.

### Terminal

Interactive terminal chat writes completed conversation exactly once to native
terminal scrollback as linear, selectable text. Run `/keys` for every binding
and `/help` for commands. Accessibility controls are:

- `NO_COLOR=1` or `--no-color` to emit no colors;
- `--no-animation` to replace the activity spinner with a static marker;
- `--plain-session` for a line-oriented interactive session without cursor
  control; and
- `--message "…"` for a single plain-output turn.

The plain modes are the preferred terminal paths for screen readers that do
not reliably track an inline repainted region. Ctrl+Z restores terminal modes
before suspending. In a permission prompt, Esc or Ctrl+C refuses and Ctrl+Z
suspends without answering.

## Current limitations and alternatives

Terminal screen-reader behavior varies by terminal emulator and assistive
technology. Runtime verification results are published in the applicable
Accessibility Conformance Report. If the interactive terminal is unsuitable,
use `--plain-session`, a single-message invocation, or either editor surface.

Garrison does not change operating-system or IDE accessibility settings. For
product-specific conformance detail, commercial customers may request the
current Voluntary Product Accessibility Templates (VPATs) from Govcraft.

## Accessibility support and accommodations

For an accessibility problem, accessible-format documentation, or help using
Garrison with assistive technology, email Roland Rodriguez at
[roland@govcraft.ai](mailto:roland@govcraft.ai) with “Garrison accessibility”
in the subject. Include the product version, surface, operating system,
assistive technology and the task you were attempting when practical; do not
include source code, credentials or other sensitive material.

Govcraft will provide support through an accessible communication channel and
will make reasonable accommodations for disability-related communication
needs. Available accommodations can include documentation in an alternative
text format, an email-based support exchange instead of a voice call, and a
remote walkthrough compatible with the customer’s assistive technology.
