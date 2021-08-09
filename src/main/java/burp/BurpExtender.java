package burp;

import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public String ExtenderName = "unidecode";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.printOutput(ExtenderName + " by 4shen0ne");
        callbacks.setExtensionName(ExtenderName);

        callbacks.registerMessageEditorTabFactory(this);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new ChineseResponseTab(controller, helpers);
    }

    class ChineseResponseTab implements IMessageEditorTab {
        private IMessageEditorController controller;
        private IExtensionHelpers helpers;
        private ITextEditor txtInput;

        private Pattern pattern = Pattern.compile("(\\\\u(\\p{XDigit}{4}))");
        private byte[] currentMessage;

        public ChineseResponseTab(IMessageEditorController controller, IExtensionHelpers helpers) {
            this.controller = controller;
            this.helpers = helpers;

            txtInput = callbacks.createTextEditor();
        }

        @Override
        public String getTabCaption() {
            return "unidecode";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return !isRequest && hasUnicode(content);
        }

        private boolean hasUnicode(byte[] content) {
            return pattern.matcher(new String(content).toLowerCase()).find();
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            IResponseInfo respInfo = helpers.analyzeResponse(content);
            // only decode response body
            String bodyContent = new String(Arrays.copyOfRange(content, respInfo.getBodyOffset(), content.length));

            txtInput.setText(currentMessage = unidecode(bodyContent));
        }

        private byte[] unidecode(String bodyContent) {
            Matcher matcher = pattern.matcher(bodyContent.toLowerCase());
            StringBuilder result = new StringBuilder();
            int index = 0;
            char decoded;
            while (matcher.find()) {
                // hex decode
                decoded = (char) Integer.parseInt(bodyContent.substring(matcher.start() + 2, matcher.end()), 16);
                result.append(bodyContent.substring(index, matcher.start()) + decoded);
                index = matcher.end();
            }
            result.append(bodyContent.substring(index));
            return String.valueOf(result).getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public byte[] getMessage() {
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }
    }
}