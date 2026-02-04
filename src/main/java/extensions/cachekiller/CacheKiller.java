/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package extensions.cachekiller;

import burp.api.montoya.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import extensions.cachekiller.Utils.Server;
import extensions.cachekiller.Workers.CacheDeceptionScanWorker;
import extensions.cachekiller.Workers.CachePoisoningScanWorker;
import extensions.cachekiller.Workers.DelimiterScanWorker;
import extensions.cachekiller.Workers.NormalizationScanWorker;

import extensions.cachekiller.Workers.ScanWorker;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public class CacheKiller implements ContextMenuItemsProvider {

    private final MontoyaApi api;

    private List<String> testDelimitersList;
    private List<String> extensionsList;
    private List<String> staticDirectories;
    private static HashMap<String, Server> servers;
    private final List<ScanWorker> activeWorkers = new CopyOnWriteArrayList<>();

    public CacheKiller(MontoyaApi api) {
        this.api = api;
        this.testDelimitersList = new ArrayList<>();
        this.staticDirectories = new ArrayList<>();
        this.extensionsList = new ArrayList<>();
        if (servers == null) servers = new HashMap<>();
    }

    public void onUnload() {
        api.logging().logToOutput("Extension Unloaded. Shutting down all active workers...");
        for (ScanWorker worker : activeWorkers) {
            worker.cancel(true);
        }
        activeWorkers.clear();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        List<HttpRequestResponse> requestResponse = new ArrayList<>(event.selectedRequestResponses());
        if (requestResponse.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            requestResponse.add(event.messageEditorRequestResponse().get().requestResponse());
        }
        if (requestResponse.isEmpty()) {
            return menuItems;
        }
        JMenuItem delimiterItem = new JMenuItem("Delimiters finder");
        JMenuItem normalizationItem = new JMenuItem("Normalization prove");
        JMenuItem cacheDecetionItem = new JMenuItem("Web Cache Deception scan");
        JMenuItem cachePoisoningItem = new JMenuItem("Web Cache Poisoning scan");
        delimiterItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showDelimiterDialog(requestResponse)));
        normalizationItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showNormalizationDialog(requestResponse)));
        cacheDecetionItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showCacheDeceptionDialog(requestResponse)));
        cachePoisoningItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showCachePoisoningDialog(requestResponse)));
        menuItems.add(delimiterItem);
        menuItems.add(normalizationItem);
        menuItems.add(cacheDecetionItem);
        menuItems.add(cachePoisoningItem);
        return menuItems;
    }

    void showDelimiterDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Delimiters Finder");
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Payload List Label
        JPanel payloadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel payloadLabel = new JLabel("Payload List");
        payloadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        payloadPanel.add(payloadLabel);
        mainPanel.add(payloadPanel);

        // Select from File Option
        JRadioButton selectFromFileButton = new JRadioButton("Select from file");
        selectFromFileButton.setActionCommand("SELECT_FROM_FILE");
        JTextField filenameField = new JTextField("filename", 10);
        JButton fileButton = new JButton("...");
        fileButton.addActionListener(e -> importFile(filenameField, testDelimitersList));
        JPanel selectFromFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectFromFilePanel.add(selectFromFileButton);
        selectFromFilePanel.add(filenameField);
        selectFromFilePanel.add(fileButton);
        mainPanel.add(selectFromFilePanel);

        // ASCII Extended Option
        JRadioButton asciiExtendedButton = new JRadioButton("ASCII - Extended");
        asciiExtendedButton.setActionCommand("ASCII_EXTENDED");
        JPanel asciiExtendedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiExtendedPanel.add(asciiExtendedButton);
        mainPanel.add(asciiExtendedPanel);

        // ASCII with Encoded Extended Option
        JRadioButton asciiWithEncodedButton = new JRadioButton("ASCII (with encoded) - Extended");
        asciiWithEncodedButton.setActionCommand("ASCII_WITH_ENCODED");
        JPanel asciiWithEncodedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiWithEncodedPanel.add(asciiWithEncodedButton);
        mainPanel.add(asciiWithEncodedPanel);

        // Group Radio Buttons
        ButtonGroup payloadGroup = new ButtonGroup();
        payloadGroup.add(selectFromFileButton);
        payloadGroup.add(asciiExtendedButton);
        payloadGroup.add(asciiWithEncodedButton);

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostDelimitersCheckbox = new JCheckBox("Detect sub hosts delimiters");
        JPanel detectSubHostDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostDelimitersOptionPanel.add(detectSubHostDelimitersCheckbox);
        mainPanel.add(detectSubHostDelimitersOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectKeyDelimitersCheckbox = new JCheckBox("Detect Key delimiters");
        JPanel detectKeyDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectKeyDelimitersOptionPanel.add(detectKeyDelimitersCheckbox);
        mainPanel.add(detectKeyDelimitersOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            String actionCommand = payloadGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (testDelimitersList == null) testDelimitersList= new ArrayList<>();
                    break;
                case "ASCII_EXTENDED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                    }
                    break;
                case "ASCII_WITH_ENCODED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                        testDelimitersList.add("%" + String.format("%02x", i));
                    }
                    break;
                default:
                    testDelimitersList = new ArrayList<>();
            }
            try {
                launchBulkScan(requestResponse, "DelimiterScan", hostRequests ->
                        new DelimiterScanWorker(api, hostRequests, testDelimitersList, fullSitemapScanCheckbox.isSelected(), detectSubHostDelimitersCheckbox.isSelected(), detectKeyDelimitersCheckbox.isSelected()));
            } catch (Throwable t) {
                api.logging().logToOutput("ERROR: Failed to start delimiter scan - " + t.getClass().getName() + ": " + t.getMessage());
            }
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setMinimumSize(new Dimension(400, dialog.getPreferredSize().height));
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }


    void showCacheDeceptionDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Web Cache Deception Scan");
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Payload List Label
        JPanel payloadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel payloadLabel = new JLabel("Delimiters List");
        payloadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        payloadPanel.add(payloadLabel);
        mainPanel.add(payloadPanel);

        // Select from File Option
        JRadioButton selectFromFileButton = new JRadioButton("Select from file");
        selectFromFileButton.setActionCommand("SELECT_FROM_FILE");
        JTextField filenameField = new JTextField("filename", 10);
        JButton fileButton = new JButton("...");
        fileButton.addActionListener(e -> importFile(filenameField, testDelimitersList));
        JPanel selectFromFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectFromFilePanel.add(selectFromFileButton);
        selectFromFilePanel.add(filenameField);
        selectFromFilePanel.add(fileButton);
        mainPanel.add(selectFromFilePanel);

        // ASCII Extended Option
        JRadioButton asciiExtendedButton = new JRadioButton("ASCII - Extended");
        asciiExtendedButton.setActionCommand("ASCII_EXTENDED");
        JPanel asciiExtendedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiExtendedPanel.add(asciiExtendedButton);
        mainPanel.add(asciiExtendedPanel);

        // ASCII with Encoded Extended Option
        JRadioButton asciiWithEncodedButton = new JRadioButton("ASCII (with encoded) - Extended");
        asciiWithEncodedButton.setActionCommand("ASCII_WITH_ENCODED");
        JPanel asciiWithEncodedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiWithEncodedPanel.add(asciiWithEncodedButton);
        mainPanel.add(asciiWithEncodedPanel);

        // Group Radio Buttons
        ButtonGroup payloadGroup = new ButtonGroup();
        payloadGroup.add(selectFromFileButton);
        payloadGroup.add(asciiExtendedButton);
        payloadGroup.add(asciiWithEncodedButton);

        // Payload List Label
        JPanel extensionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel extensionLabel = new JLabel("Static Extension List");
        extensionLabel.setFont(new Font("Arial", Font.BOLD, 12));
        extensionPanel.add(extensionLabel);
        mainPanel.add(extensionPanel);

        // Select from File Option
        JRadioButton fileExtensionButton = new JRadioButton("Select from file");
        fileExtensionButton.setActionCommand("SELECT_FROM_FILE");
        JTextField fileExtensionField = new JTextField("filename", 10);
        JButton filesButton = new JButton("...");
        filesButton.addActionListener(e -> importFile(fileExtensionField, extensionsList));
        JPanel fileExtensionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileExtensionPanel.add(fileExtensionButton);
        fileExtensionPanel.add(fileExtensionField);
        fileExtensionPanel.add(filesButton);
        mainPanel.add(fileExtensionPanel);

        // ASCII Extended Option
        JRadioButton simpleListButton = new JRadioButton("simple list (js, ico, exe)");
        simpleListButton.setActionCommand("SIMPLE_LIST");
        JPanel simpleListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        simpleListPanel.add(simpleListButton);
        mainPanel.add(simpleListPanel);

        // ASCII with Encoded Extended Option
        JRadioButton extendedListButton = new JRadioButton("extended list (css, js, ico, exe, png)");
        extendedListButton.setActionCommand("EXTENDED_LIST");
        JPanel extendedListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        extendedListPanel.add(extendedListButton);
        mainPanel.add(extendedListPanel);

        // Group Radio Buttons
        ButtonGroup extensionGroup = new ButtonGroup();
        extensionGroup.add(fileExtensionButton);
        extensionGroup.add(simpleListButton);
        extensionGroup.add(extendedListButton);

        // Payload List Label
        JPanel staticDirPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel staticDirLabel = new JLabel("Static Directories List");
        staticDirLabel.setFont(new Font("Arial", Font.BOLD, 12));
        staticDirPanel.add(staticDirLabel);
        mainPanel.add(staticDirPanel);

        // Select from File Option
        JRadioButton staticDirButton = new JRadioButton("Select from file");
        staticDirButton.setActionCommand("SELECT_FROM_FILE");
        JTextField staticDirField = new JTextField("filename", 10);
        JButton filesDirButton = new JButton("...");
        filesDirButton.addActionListener(e -> importFile(staticDirField, staticDirectories));
        JPanel staticDirFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        staticDirFilePanel.add(staticDirButton);
        staticDirFilePanel.add(staticDirField);
        staticDirFilePanel.add(filesDirButton);
        mainPanel.add(staticDirFilePanel);

        // ASCII Extended Option
        JRadioButton staticDirListButton = new JRadioButton("Use classic static directories");
        staticDirListButton.setActionCommand("BASE_LIST");
        JPanel staticDirListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        staticDirListPanel.add(staticDirListButton);
        mainPanel.add(staticDirListPanel);

        // ASCII with Encoded Extended Option
        JRadioButton detectButton = new JRadioButton("Detect static directories (slow)");
        detectButton.setActionCommand("DETECT");
        JPanel detectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectPanel.add(detectButton);
        mainPanel.add(detectPanel);

        // Group Radio Buttons
        ButtonGroup staticDirGroup = new ButtonGroup();
        staticDirGroup.add(staticDirButton);
        staticDirGroup.add(staticDirListButton);
        staticDirGroup.add(detectButton);

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostDelimitersCheckbox = new JCheckBox("Detect sub hosts delimiters");
        JPanel detectSubHostDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostDelimitersOptionPanel.add(detectSubHostDelimitersCheckbox);
        mainPanel.add(detectSubHostDelimitersOptionPanel);

        // Report Detection Results Option
        JCheckBox reportDetectionResultsCheckbox = new JCheckBox("Report detection results");
        JPanel reportDetectionResultsOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        reportDetectionResultsOptionPanel.add(reportDetectionResultsCheckbox);
        mainPanel.add(reportDetectionResultsOptionPanel);

        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            String actionCommand = payloadGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (testDelimitersList == null) testDelimitersList= new ArrayList<>();
                    break;
                case "ASCII_EXTENDED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                    }
                    break;
                case "ASCII_WITH_ENCODED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                        testDelimitersList.add("%" + String.format("%02x", i));
                    }
                    break;
                default:
                    testDelimitersList = new ArrayList<>();
            }
            actionCommand = extensionGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (extensionsList == null) extensionsList= new ArrayList<>();
                    break;
                case "SIMPLE_LIST":
                    extensionsList = new ArrayList<>();
                    extensionsList.add("js");
                    extensionsList.add("ico");
                    extensionsList.add("exe");
                    extensionsList.add("css");
                    extensionsList.add("png");
                    break;
                case "EXTENDED_LIST":
                    // Pulled from seclists Discovery/Web-Content/web-extensions.txt
                    extensionsList = new ArrayList<>();
                    extensionsList.add("ico");
                    extensionsList.add("png");
                    extensionsList.add("asp");
                    extensionsList.add("aspx");
                    extensionsList.add("bat");
                    extensionsList.add("c");
                    extensionsList.add("cfm");
                    extensionsList.add("cgi");
                    extensionsList.add("css");
                    extensionsList.add("com");
                    extensionsList.add("dll");
                    extensionsList.add("exe");
                    extensionsList.add("hta");
                    extensionsList.add("htm");
                    extensionsList.add("html");
                    extensionsList.add("inc");
                    extensionsList.add("jhtml");
                    extensionsList.add("js");
                    extensionsList.add("jsa");
                    extensionsList.add("json");
                    extensionsList.add("jsp");
                    extensionsList.add("log");
                    extensionsList.add("mdb");
                    extensionsList.add("nsf");
                    extensionsList.add("pcap");
                    extensionsList.add("php");
                    extensionsList.add("php2");
                    extensionsList.add("php3");
                    extensionsList.add("php4");
                    extensionsList.add("php5");
                    extensionsList.add("php6");
                    extensionsList.add("php7");
                    extensionsList.add("phps");
                    extensionsList.add("pht");
                    extensionsList.add("phtml");
                    extensionsList.add("pl");
                    extensionsList.add("phar");
                    extensionsList.add("rb");
                    extensionsList.add("reg");
                    extensionsList.add("sh");
                    extensionsList.add("shtml");
                    extensionsList.add("sql");
                    extensionsList.add("swf");
                    extensionsList.add("txt");
                    extensionsList.add("xml");
                    break;
                default:
                    extensionsList = new ArrayList<>();
                    extensionsList.add("css");
            }

            actionCommand = staticDirGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (staticDirectories == null) staticDirectories= new ArrayList<>();
                    break;
                case "BASE_LIST":
                    staticDirectories = new ArrayList<>();
                    staticDirectories.add("/static");
                    staticDirectories.add("/resources");
                    staticDirectories.add("/shared");
                    staticDirectories.add("/public");
                    staticDirectories.add("/assets");
                    staticDirectories.add("/wp-content");
                    staticDirectories.add("/media");
                    staticDirectories.add("images");
                    break;
                case "DETECT":
                    staticDirectories = null;
                    break;
                default:
                    staticDirectories = new ArrayList<>();
            }
            try {
                launchBulkScan(requestResponse, "CacheDeceptionScan", hostRequests ->
                        new CacheDeceptionScanWorker(api, hostRequests, testDelimitersList, fullSitemapScanCheckbox.isSelected(), detectSubHostDelimitersCheckbox.isSelected(), extensionsList, staticDirectories, reportDetectionResultsCheckbox.isSelected()));
            } catch (Throwable t) {
                api.logging().logToOutput("ERROR: Failed to start cache deception scan - " + t.getClass().getName() + ": " + t.getMessage());
            }
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setMinimumSize(new Dimension(400, dialog.getPreferredSize().height));
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }



    void showCachePoisoningDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Web Cache Poisoning Scan");
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Payload List Label
        JPanel payloadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel payloadLabel = new JLabel("Delimiters List");
        payloadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        payloadPanel.add(payloadLabel);
        mainPanel.add(payloadPanel);

        // Select from File Option
        JRadioButton selectFromFileButton = new JRadioButton("Select from file");
        selectFromFileButton.setActionCommand("SELECT_FROM_FILE");
        JTextField filenameField = new JTextField("filename", 10);
        JButton fileButton = new JButton("...");
        fileButton.addActionListener(e -> importFile(filenameField, testDelimitersList));
        JPanel selectFromFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectFromFilePanel.add(selectFromFileButton);
        selectFromFilePanel.add(filenameField);
        selectFromFilePanel.add(fileButton);
        mainPanel.add(selectFromFilePanel);

        // ASCII Extended Option
        JRadioButton asciiExtendedButton = new JRadioButton("ASCII - Extended");
        asciiExtendedButton.setActionCommand("ASCII_EXTENDED");
        JPanel asciiExtendedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiExtendedPanel.add(asciiExtendedButton);
        mainPanel.add(asciiExtendedPanel);

        // ASCII with Encoded Extended Option
        JRadioButton asciiWithEncodedButton = new JRadioButton("ASCII (with encoded) - Extended");
        asciiWithEncodedButton.setActionCommand("ASCII_WITH_ENCODED");
        JPanel asciiWithEncodedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiWithEncodedPanel.add(asciiWithEncodedButton);
        mainPanel.add(asciiWithEncodedPanel);

        // Group Radio Buttons
        ButtonGroup payloadGroup = new ButtonGroup();
        payloadGroup.add(selectFromFileButton);
        payloadGroup.add(asciiExtendedButton);
        payloadGroup.add(asciiWithEncodedButton);

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostDelimitersCheckbox = new JCheckBox("Detect sub hosts");
        JPanel detectSubHostDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostDelimitersOptionPanel.add(detectSubHostDelimitersCheckbox);
        mainPanel.add(detectSubHostDelimitersOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            String actionCommand = payloadGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (testDelimitersList == null) testDelimitersList= new ArrayList<>();
                    break;
                case "ASCII_EXTENDED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                    }
                    break;
                case "ASCII_WITH_ENCODED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                        testDelimitersList.add("%" + String.format("%02x", i));
                    }
                    break;
                default:
                    testDelimitersList = new ArrayList<>();
            }
            try {
                launchBulkScan(requestResponse, "CachePoisoningScan", hostRequests ->
                        new CachePoisoningScanWorker(api, hostRequests, testDelimitersList, fullSitemapScanCheckbox.isSelected(), detectSubHostDelimitersCheckbox.isSelected()));
            } catch (Throwable t) {
                api.logging().logToOutput("ERROR: Failed to start cache poisoning scan - " + t.getClass().getName() + ": " + t.getMessage());
            }
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setMinimumSize(new Dimension(400, dialog.getPreferredSize().height));
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }




    void showNormalizationDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Normalization Probe");
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostNormalizationCheckbox = new JCheckBox("Detect sub hosts normalization");
        JPanel detectSubHostNormalizationOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostNormalizationOptionPanel.add(detectSubHostNormalizationCheckbox);
        mainPanel.add(detectSubHostNormalizationOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectKeyNormalizationCheckbox = new JCheckBox("Detect Key normalization");
        JPanel detectKeyNormalizationOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectKeyNormalizationOptionPanel.add(detectKeyNormalizationCheckbox);
        mainPanel.add(detectKeyNormalizationOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            try {
                launchBulkScan(requestResponse, "NormalizationScan", hostRequests ->
                        new NormalizationScanWorker(api, hostRequests, fullSitemapScanCheckbox.isSelected(), detectSubHostNormalizationCheckbox.isSelected(), detectKeyNormalizationCheckbox.isSelected()));
            } catch (Throwable t) {
                api.logging().logToOutput("ERROR: Failed to start normalization scan - " + t.getClass().getName() + ": " + t.getMessage());
            }
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setMinimumSize(new Dimension(400, dialog.getPreferredSize().height));
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }


    @FunctionalInterface
    private interface WorkerFactory {
        ScanWorker create(List<HttpRequestResponse> hostRequests);
    }

    private void launchBulkScan(List<HttpRequestResponse> requestResponse, String scanType, WorkerFactory factory) {
        // Group requests by host
        Map<String, List<HttpRequestResponse>> hostGroups = new LinkedHashMap<>();
        for (HttpRequestResponse rr : requestResponse) {
            hostGroups.computeIfAbsent(rr.httpService().host(), k -> new ArrayList<>()).add(rr);
        }

        int totalHosts = hostGroups.size();
        AtomicInteger completedCount = new AtomicInteger(0);

        for (Map.Entry<String, List<HttpRequestResponse>> entry : hostGroups.entrySet()) {
            String host = entry.getKey();
            List<HttpRequestResponse> hostRequests = entry.getValue();

            ScanWorker worker = factory.create(hostRequests);
            worker.setOnComplete(() -> {
                activeWorkers.remove(worker);
                int done = completedCount.incrementAndGet();
                int remaining = totalHosts - done;
                api.logging().logToOutput("[CacheKiller] Scan completed for " + host + " (" + done + "/" + totalHosts + " hosts done, " + remaining + " remaining)");
                if (done == totalHosts) {
                    api.logging().logToOutput("[CacheKiller] All scans complete.");
                }
            });
            activeWorkers.add(worker);
            api.logging().logToOutput("[CacheKiller] Queued " + scanType + " for " + host + " (" + hostRequests.size() + " requests)");
            worker.execute();
        }
    }

    private void importFile(JTextField filenameField, List<String> targetList) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filenameField.setText(selectedFile.getName());
            try {
                List<String> lines = Files.readAllLines(selectedFile.toPath(), StandardCharsets.UTF_8);
                targetList.clear();
                for (String line : lines) {
                    targetList.add(new String(line.getBytes(StandardCharsets.UTF_8), StandardCharsets.US_ASCII));
                }
                JOptionPane.showMessageDialog(null, "File imported successfully.");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Error importing file: " + ex.getMessage());
            }
        }
    }


}