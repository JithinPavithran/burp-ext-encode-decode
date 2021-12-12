package burp;

import Utils.UIHelper;
import encode.Encoder;
import encode.None;
import encode.UnicodeSlashU;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    private final String name = "Encode Decode";
    private final String tabName = "encDec";

    private boolean enabled = false;

    Pattern methodPattern;
    Pattern hostPattern;
    Pattern portPattern;
    Pattern pathPattern;

    JCheckBox enableCheckBox;
    JLabel enableLabel;
    JTextField methodField;
    JTextField hostnameField;
    JTextField portField;
    JTextField pathField;
    JButton pasteUrlButton;

    private List<Encoder> encoderList = new ArrayList<>();
    private List<Encoder> selectedEncoders;
    JPanel decoderPanel;

    private JPanel tabUi;
    public PrintWriter stdout;
    public PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers; // in case required in the future :)

    public BurpExtender() { }

    private void initComponents() {
        this.encoderList.add(new None());  // CAUTION: This should always be the 1st encoder
        this.encoderList.add(new UnicodeSlashU());
        // Add new encoders here
    }

    public String getName() {
        return "Encoding / Decoding";
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName(this.name);
        initComponents();
        this.createTabUi();
        callbacks.addSuiteTab(this);
        this.helpers = callbacks.getHelpers();
        callbacks.registerHttpListener(this);
        this.stdout.println("Loaded " + this.name + " Extension");
    }
    /**
     * This method is invoked when an HTTP request is about to be issued, and
     * when an HTTP response has been received.
     *
     * @param toolFlag         A flag indicating the Burp tool that issued the request.
     *                         Burp tool flags are defined in the
     *                         <code>IBurpExtenderCallbacks</code> interface.
     * @param messageIsRequest Flags whether the method is being invoked for a
     *                         request or response.
     * @param messageInfo      Details of the request / response to be processed.
     *                         Extensions can call the setter methods on this object to update the
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        ProxyMessageContainer pmc = new ProxyMessageContainer(messageInfo);
        if (!this.inFilter(pmc)) {
            return;
        }
        if (messageIsRequest) {
            ;
        } else {
            for(Encoder e: this.selectedEncoders) {
                pmc.setResponse(e.decode(pmc.getResponse()));
            }
        }
    }

    boolean verifyAndSetFilter() {
        // Method
        String method = this.methodField.getText().trim();
        if ("".equals(method)) {
            this.methodField.setText(method = ".*");
        }
        try {
            this.methodPattern = Pattern.compile(method);
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(null,
                    "Method is not valid regex.",
                    "Invalid Method", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        // Check hostname
        String hostname = this.hostnameField.getText().trim();
        if ("".equals(hostname)) {
            JOptionPane.showMessageDialog(null,
                    "Hostname is empty.",
                    "Invalid Hostname", JOptionPane.ERROR_MESSAGE);
            this.enableCheckBox.setSelected(false);
            return false;
        }
        try {
            this.hostPattern = Pattern.compile(hostname);
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(null,
                    "Hostname is not valid regex.",
                    "Invalid Hostname", JOptionPane.ERROR_MESSAGE);
            this.enableCheckBox.setSelected(false);
            return false;
        }
        // Port
        String port = this.portField.getText().trim();
        if ("".equals(port)) {
            this.portField.setText(port = ".*");
        }
        try {
            this.portPattern = Pattern.compile(port);
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(null,
                    "Port is not valid regex.",
                    "Invalid Port", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        // check path
        String path = this.pathField.getText().trim();
        if ("".equals(path)) {
            this.pathField.setText(path = ".*");
        }
        try {
            this.pathPattern = Pattern.compile(path);
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(null,
                    "URL is not valid regex.",
                    "Invalid URL", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    void setFilterEditable(boolean yes) {
        this.methodField.setEditable(yes);
        this.hostnameField.setEditable(yes);
        this.portField.setEditable(yes);
        this.pathField.setEditable(yes);
        this.pasteUrlButton.setEnabled(yes);
        this.enableLabel.setVisible(!yes);
    }

    public void setEnabled(boolean enable) {
        if (enable) {
            enable = this.verifyAndSetFilter();
        }
        if (enable) {
            this.selectedEncoders = new ArrayList<>();
            for (Component c: this.decoderPanel.getComponents()) {
                this.selectedEncoders.add(
                        this.encoderList.get(
                                ((JComboBox)c).getSelectedIndex()
                        )
                );
            }
        }
        this.setFilterEditable(!enable);
        for (Component c: this.decoderPanel.getComponents()) {
            c.setEnabled(!enable);
        }
        this.enabled = enable;
    }

    boolean inFilter(ProxyMessageContainer pmc) {
        return this.enabled &&
                this.methodPattern.matcher(pmc.getMethod()).matches() &&
                this.hostPattern.matcher(pmc.getHostname()).matches() &&
                this.portPattern.matcher(pmc.getPort()).matches() &&
                this.pathPattern.matcher(pmc.getPath()).matches();
    }

    @Override
    public String getTabCaption() {
        return this.tabName;
    }

    /**
     * Burp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    @Override
    public Component getUiComponent() {
        return tabUi;
    }

    private void createTabUi() {
        this.tabUi = new JPanel();
        this.tabUi.setLayout(new BorderLayout());
        this.tabUi.add(this.getPanel(), BorderLayout.PAGE_START);
        callbacks.customizeUiComponent(tabUi);
        System.gc();
    }

    void addDropBox() {
        List<String> dropBoxList = new ArrayList<>();
        for (Encoder e: this.encoderList) {
            dropBoxList.add(e.getName());
        }
        JComboBox dropBox = new JComboBox(dropBoxList.toArray());
        dropBox.addItemListener(itemEvent -> {
            if (itemEvent.getStateChange() == ItemEvent.SELECTED) {
                Component[] components = this.decoderPanel.getComponents();
                if (dropBox.getSelectedIndex() != 0) {
                    // If last drop box is not "None", add a new dropbox (to make the last one None)
                    // Ideally, you need to check this only if the value of last dropbox was changed,
                    //          but it is easier to do like this.
                    if (((JComboBox)components[components.length-1]).getSelectedIndex() != 0) {
                        this.addDropBox();
                    }
                }
                if (dropBox.getSelectedIndex() == 0) {
                    // if the second last drop box has "None" selected, remove it
                    // (last drop box will always have "None")
                    // Ideally you need to do this only when the value of second last dropbox changes,
                    //          but it is easier to do like this.
                    while (components.length > 1 &&
                            ((JComboBox)components[components.length-2]).getSelectedIndex() == 0) {
                        this.decoderPanel.remove(components[components.length-2]);
                        components = this.decoderPanel.getComponents();
                    }
                }
            }
        });
        this.decoderPanel.add(dropBox);
    }

    public JPanel getPanel() {
        JPanel pane = new JPanel();
        pane.setLayout(new GridBagLayout());
        GridBagConstraints c = UIHelper.getDefaultGBC();

        c.anchor = GridBagConstraints.LINE_START;
        c.weightx = 1;
        c.gridwidth = 6;
        c.gridx = 0;
        c.gridy = 0;
        pane.add(this.getFilterPanel(), c);

        this.decoderPanel = new JPanel();
        this.decoderPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        addDropBox();
        c.gridy = c.gridy + 1;
        pane.add(decoderPanel, c);

        this.setEnabled(false);
        return pane;
    }

    JPanel getFilterPanel() {
        this.enableCheckBox = new JCheckBox("Enable " + this.getName());
        this.enableLabel = new JLabel("<html>Encoding/Decoding enabled and configs blocked." +
                " Disable to configure again <span style=\"color:green\">⬤</span></html>", SwingConstants.RIGHT);
        this.methodField = new JTextField(".*", 8);
        this.hostnameField = new JTextField("", 36);
        this.portField = new JTextField(".*", 8);
        this.pathField = new JTextField(".*");
        UIHelper.setMonospaceFont(methodField, hostnameField, portField, pathField);
        this.enableCheckBox.addItemListener(e -> {
            setEnabled(e.getStateChange() == ItemEvent.SELECTED);
        });

        JPanel pane = new JPanel();
        pane.setLayout(new GridBagLayout());
        GridBagConstraints c = UIHelper.getDefaultGBC();

        // Title   ... Encode / Decode ...
        JLabel titlePane = new JLabel(this.getName(), SwingConstants.CENTER);
        Font font = titlePane.getFont();
        titlePane.setFont(font.deriveFont(font.getStyle() | Font.BOLD));
        c.anchor = GridBagConstraints.CENTER;
        c.weightx = 1;
        c.gridwidth = 6;
        pane.add(titlePane, c);

        // [ ] Drop request with ...     ... Encode/Decode enabled
        JPanel checkBoxPane1 = new JPanel();
        checkBoxPane1.setLayout(new BoxLayout(checkBoxPane1, BoxLayout.X_AXIS));
        checkBoxPane1.add(this.enableCheckBox);
        checkBoxPane1.add(Box.createHorizontalGlue());
        checkBoxPane1.add(this.enableLabel);
        c.anchor = GridBagConstraints.LINE_START;
        c.gridy = c.gridy + 1;
        pane.add(checkBoxPane1, c);

        //  button panel ... [Parse and paste URL]
        this.pasteUrlButton = new JButton("Parse and paste URL");
        this.pasteUrlButton.addActionListener(actionEvent -> {
            try {
                UIHelper.pasteUrlFromClipboard(null, this.hostnameField, this.portField, this.pathField);
            } catch (BurpException e) {
                JOptionPane.showMessageDialog(null,
                        e.getShowMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                this.stderr.println(Arrays.toString(e.getStackTrace()));
            }
        });
        JPanel buttonPane = new JPanel();
        buttonPane.setLayout(new BoxLayout(buttonPane, BoxLayout.X_AXIS));
        buttonPane.add(this.pasteUrlButton);
        c.gridy = c.gridy + 1;
        pane.add(buttonPane, c);

        // Method (.*) [___] Hostname (.*) [________]  Port (.*) [___]
        c.gridwidth = 1;
        c.gridy = c.gridy + 1;
        // method
        c.weightx = 0;
        pane.add(new JLabel("Method (.*)"), c);
        c.gridx = c.gridx + 1;
        c.weightx = 0.2;
        pane.add(this.methodField, c);
        // hostname
        c.gridx = c.gridx + 1;
        c.weightx = 0;
        pane.add(new JLabel("Hostname (.*)"), c);
        c.gridx = c.gridx + 1;
        c.weightx = 1;
        pane.add(this.hostnameField, c);
        // port
        c.gridx = c.gridx + 1;
        c.weightx = 0;
        pane.add(new JLabel("Port (.*)"), c);
        c.gridx = c.gridx + 1;
        c.weightx = 0.2;
        pane.add(this.portField, c);

        // Path (regex) [______]
        c.gridx = 0;
        c.gridy = c.gridy + 1;
        c.weightx = 0;
        pane.add(new JLabel("Path (.*)"), c);
        c.gridx = c.gridx + 1;
        c.gridwidth = 5;
        c.weightx = 1;
        pane.add(this.pathField, c);

        return pane;
    }
}
