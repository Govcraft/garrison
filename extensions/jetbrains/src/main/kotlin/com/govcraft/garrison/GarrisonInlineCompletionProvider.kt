package com.govcraft.garrison

import com.google.gson.JsonObject
import com.intellij.codeInsight.inline.completion.InlineCompletionEvent
import com.intellij.codeInsight.inline.completion.InlineCompletionProvider
import com.intellij.codeInsight.inline.completion.InlineCompletionProviderID
import com.intellij.codeInsight.inline.completion.InlineCompletionRequest
import com.intellij.codeInsight.inline.completion.elements.InlineCompletionGrayTextElement
import com.intellij.codeInsight.inline.completion.suggestion.InlineCompletionSingleSuggestion
import com.intellij.codeInsight.inline.completion.suggestion.InlineCompletionSuggestion
import com.intellij.openapi.application.readAction
import com.intellij.openapi.diagnostic.Logger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.await

/**
 * Ghost text from `garrison-agent`, over the same governed connection the tool
 * window uses.
 *
 * This class is Kotlin because the API is: [InlineCompletionProvider] declares
 * its work as a suspend function and identifies providers with an inline value
 * class, and Java can implement neither. The rest of the plugin stays Java,
 * and everything this talks to — [GarrisonConnection], the settings — is Java
 * too.
 *
 * # Why the debounce is here rather than inherited
 *
 * The platform ships `DebouncedInlineCompletionProvider`, whose delay hook is
 * deprecated in 2025.3 in favour of an overload that version does not actually
 * declare. Rather than override a deprecated method or suppress the warning,
 * the debounce is a cancellable [delay] at the top of [getSuggestion]: the
 * platform cancels this coroutine when the developer types again, which aborts
 * the delay and is precisely the behaviour being asked for.
 *
 * The provider does nothing clever with the suggestion it gets back. Stripping
 * the code fences and the restated prefix a chat model wraps around a
 * completion is logic worth having once, tested, in the agent, rather than
 * reimplemented in every editor client.
 */
internal class GarrisonInlineCompletionProvider : InlineCompletionProvider {
    private companion object {
        val LOG = Logger.getInstance(GarrisonInlineCompletionProvider::class.java)

        /** How much text on each side of the cursor is worth sending. */
        const val PREFIX_BUDGET = 4_000
        const val SUFFIX_BUDGET = 1_000

        /**
         * How long the agent is left alone after a failure.
         *
         * Without this, an agent that cannot start is asked to complete on
         * every keystroke and fails every time — which turns one
         * misconfiguration into a stream of them, while somebody is typing.
         */
        const val FAILURE_COOLDOWN_MS = 30_000L
    }

    @Volatile
    private var coolingUntil = 0L

    override val id: InlineCompletionProviderID = InlineCompletionProviderID("Garrison")

    /**
     * Whether this event should produce a suggestion at all.
     *
     * Typing and an explicit invocation both qualify; everything else — a
     * lookup being navigated, a document opening — does not, because ghost
     * text that appears without the developer having typed anything reads as
     * the editor acting on its own.
     */
    override fun isEnabled(event: InlineCompletionEvent): Boolean {
        if (!GarrisonSettings.getInstance().state.inlineCompletionEnabled) return false
        return event is InlineCompletionEvent.DocumentChange || event is InlineCompletionEvent.DirectCall
    }

    override suspend fun getSuggestion(request: InlineCompletionRequest): InlineCompletionSuggestion {
        // An explicit invocation is a decision, so it waits for nothing and
        // ignores the cooldown: the developer asked, and is owed an attempt.
        val forced = request.event is InlineCompletionEvent.DirectCall
        if (!forced) {
            if (System.currentTimeMillis() < coolingUntil) return InlineCompletionSuggestion.Empty
            val settings = GarrisonSettings.getInstance().state
            delay(settings.inlineCompletionDebounceMs.coerceIn(0, 5_000).toLong())
        }

        val project = request.editor.project ?: return InlineCompletionSuggestion.Empty
        val file = request.file.virtualFile

        // Reading the document has to happen under a read action, and the
        // offset has to be clamped: this runs off the EDT, so the document may
        // have grown or shrunk since the request was built.
        val cursor = readAction {
            val text = request.document.immutableCharSequence.toString()
            val offset = request.endOffset.coerceIn(0, text.length)
            Cursor(
                prefix = text.substring(0, offset).takeLast(PREFIX_BUDGET),
                suffix = text.substring(offset).take(SUFFIX_BUDGET),
            )
        }

        // Nothing above the cursor is nothing to continue from.
        if (cursor.prefix.isBlank()) return InlineCompletionSuggestion.Empty

        val params = JsonObject().apply {
            addProperty("prefix", cursor.prefix)
            addProperty("suffix", cursor.suffix)
            if (file != null) addProperty("uri", file.url)
            addProperty("languageId", request.file.language.id.lowercase())
        }

        val completion = try {
            val connection = GarrisonConnection.getInstance(project)
            params.addProperty("sessionId", connection.session())
            val response = connection.request("_garrison/complete", params).await()
            response.get("completion")?.takeIf { it.isJsonPrimitive }?.asString.orEmpty()
        } catch (cancellation: CancellationException) {
            // The developer moved on. Not a failure, and not worth a cooldown.
            throw cancellation
        } catch (error: Exception) {
            // A failed completion is never worth a dialog: it is speculative
            // work the developer did not ask for and is not waiting on.
            LOG.warn("Garrison inline completion failed", error)
            coolingUntil = System.currentTimeMillis() + FAILURE_COOLDOWN_MS
            return InlineCompletionSuggestion.Empty
        }

        if (completion.isEmpty()) return InlineCompletionSuggestion.Empty

        return InlineCompletionSingleSuggestion.build {
            emit(InlineCompletionGrayTextElement(completion))
        }
    }

    /** The text on either side of the cursor, already trimmed to budget. */
    private data class Cursor(val prefix: String, val suffix: String)
}
