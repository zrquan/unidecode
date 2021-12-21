package burp

import kotlin.text.Regex
import java.awt.Component

const val EXTENDER_NAME = "unidecode"

class BurpExtender : IBurpExtender {
    private lateinit var callbacks: IBurpExtenderCallbacks

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        callbacks.printOutput("$EXTENDER_NAME by 4shen0ne")
        callbacks.setExtensionName(EXTENDER_NAME)
        callbacks.registerMessageEditorTabFactory { controller, _ ->
            ChineseResponseTab(controller, callbacks)
        }
    }
}

class ChineseResponseTab(
    controller: IMessageEditorController, callbacks: IBurpExtenderCallbacks
) : IMessageEditorTab {
    private val txtInput: ITextEditor = callbacks.createTextEditor()
    private val helpers: IExtensionHelpers = callbacks.helpers
    private val regex: Regex = Regex("(\\\\u(\\p{XDigit}{4}))")
    private lateinit var currentMessage: ByteArray

    override fun getMessage(): ByteArray = currentMessage
    override fun getTabCaption(): String = EXTENDER_NAME
    override fun isModified(): Boolean = txtInput.isTextModified
    override fun getSelectedData(): ByteArray = txtInput.selectedText
    override fun getUiComponent(): Component = txtInput.component

    override fun isEnabled(
        content: ByteArray, isRequest: Boolean
    ): Boolean = !isRequest && hasUnicode(content)

    private fun hasUnicode(content: ByteArray): Boolean {
        return regex.containsMatchIn(String(content).lowercase())
    }

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        val respInfo: IResponseInfo = helpers.analyzeResponse(content)
        // only decode response body
        val bodyContent = String(content.copyOfRange(respInfo.bodyOffset, content.size))
        txtInput.text = unidecode(bodyContent).also { currentMessage = it }
    }

    private fun unidecode(bodyContent: String): ByteArray =
        regex.replace(bodyContent.lowercase()) {
            it.value.substring(2).toInt(16).toChar().toString()
        }.toByteArray()
}
