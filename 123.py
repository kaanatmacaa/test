#!/usr/bin/env python
# -*- coding: utf-8 -*-

#KAAN ATMACA BURP EXTENTION

from burp import ITab
from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IMessageEditorController
from javax.swing import JList
from javax.swing import JTable
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JToggleButton
from javax.swing import JCheckBox
from javax.swing import JMenuItem
from javax.swing import JTextArea
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JEditorPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing.table import TableRowSorter
from javax.swing.table import AbstractTableModel
from javax.swing.text.html import HTMLEditorKit
from threading import Lock
from java.net import URL
from java.net import URLEncoder
from java.awt import Color
from java.awt import Dimension
from java.awt import BorderLayout
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.event import AdjustmentListener
from java.util import LinkedList
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Integer
from java.lang import String
from java.lang import Math
from thread import start_new_thread
from array import array
import datetime
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQL Kaan")
        
        self._log = ArrayList()
        self._lock = Lock()
        self.intercept = 0

        self.FOUND = "SQL Found"
        self.CHECK = "Possible SQLi"
        self.HTTP_500 = "HTTP 500 Error"
        self.NOT_FOUND = "Safe"
        
        self.sql_payloads = [
            "'",
            "' OR '1'='1",
            "' AND 1=2--",
            "' UNION SELECT NULL--",
            "%27and%28select%2afrom%28select%28sleep%285%29%29%29a%29--"
        ]
        
        self.sql_errors = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "PostgreSQL.*ERROR", 
            "Warning.*pg_.*",
            "Driver.*SQL.*Server",
            "OLE DB.*SQL Server",
            "Warning.*mssql_.*",
            "Oracle error",
            "Oracle.*Driver", 
            "Warning.*oci_.*",
            "SQLite.Exception",
            "Warning.*sqlite_.*",
            "check the manual that corresponds to your",
            "You have an error",
            "syntax error",
            "SQL syntax",
            "SQL statement",
            "ERROR:",
            "Error:",
            "MySQL",
            "Warning:",
            "mysql_fetch_array()",
            "Unclosed quotation mark",
            "Incorrect syntax near"
        ]


        self.initializeUI()
        self.definecallbacks()

        print("SQL Injection Detector loaded successfully!")
        print("Focused detection with 5 targeted payloads")

    def initializeUI(self):
        self.createConfigTab()
        self.createViewers()
        self.createMainLayout()

    def createConfigTab(self):
        Config = JLabel("SQL Injection Detection Config")
        self.startButton = JToggleButton("Intercept Off", actionPerformed=self.startOrStop)
        self.startButton.setBounds(40, 30, 200, 30)

        self.autoScroll = JCheckBox("Auto Scroll")
        self.autoScroll.setBounds(40, 80, 200, 30)

        self.sqlicheck = JCheckBox("Enable SQL Injection Detection")
        self.sqlicheck.setSelected(True)
        self.sqlicheck.setBounds(40, 110, 250, 30)
        

        self.statusLabel = JLabel("Status: Ready")
        self.statusLabel.setBounds(40, 150, 300, 30)

        self.configtab = JPanel()
        self.configtab.setLayout(None)
        self.configtab.setBounds(0, 0, 400, 300)
        self.configtab.add(Config)
        self.configtab.add(self.startButton)
        self.configtab.add(self.autoScroll)
        self.configtab.add(self.sqlicheck)
        self.configtab.add(self.statusLabel)

    def createViewers(self):

        self.textfield = JEditorPane("text/html", "")
        self.kit = HTMLEditorKit()
        self.textfield.setEditorKit(self.kit)
        self.doc = self.textfield.getDocument()
        self.textfield.setEditable(0)
        self.advisorypanel = JScrollPane()
        self.advisorypanel.getVerticalScrollBar()
        self.advisorypanel.setPreferredSize(Dimension(300, 450))
        self.advisorypanel.getViewport().setView(self.textfield)


        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        self._texteditor = self._callbacks.createTextEditor()
        self._texteditor.setEditable(False)

    def createMainLayout(self):

        self.logTable = Table(self)
        tableWidth = self.logTable.getPreferredSize().width
        self.logTable.getColumn("#").setPreferredWidth(Math.round(tableWidth / 50 * 3))
        self.logTable.getColumn("Method").setPreferredWidth(Math.round(tableWidth / 50 * 5))
        self.logTable.getColumn("URL").setPreferredWidth(Math.round(tableWidth / 50 * 30))
        self.logTable.getColumn("Parameters").setPreferredWidth(Math.round(tableWidth / 50 * 5))
        self.logTable.getColumn("SQL Status").setPreferredWidth(Math.round(tableWidth / 50 * 10))
        self.logTable.getColumn("Request Time").setPreferredWidth(Math.round(tableWidth / 50 * 7))

        self.tableSorter = TableRowSorter(self)
        self.logTable.setRowSorter(self.tableSorter)


        self._bottomsplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._bottomsplit.setDividerLocation(400)
        self._bottomsplit.setLeftComponent(self.configtab)


        self.tabs = JTabbedPane()
        self.tabs.addTab("Advisory", self.advisorypanel)
        self.tabs.addTab("Request", self._requestViewer.getComponent())
        self.tabs.addTab("Response", self._responseViewer.getComponent())
        self.tabs.addTab("Highlighted Response", self._texteditor.getComponent())
        self._bottomsplit.setRightComponent(self.tabs)
        

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setDividerLocation(450)
        self._splitpane.setResizeWeight(1)
        self.scrollPane = JScrollPane(self.logTable)
        self._splitpane.setLeftComponent(self.scrollPane)
        self.scrollPane.getVerticalScrollBar().addAdjustmentListener(autoScrollListener(self))
        self._splitpane.setRightComponent(self._bottomsplit)

    def startOrStop(self, event):
        if self.startButton.getText() == "Intercept Off":
            self.startButton.setText("Intercept On")
            self.startButton.setSelected(True)
            self.intercept = 1
            self.statusLabel.setText("Status: Intercepting and scanning for SQL injection")
        else:
            self.startButton.setText("Intercept Off")
            self.startButton.setSelected(False)
            self.intercept = 0
            self.statusLabel.setText("Status: Ready")

    def definecallbacks(self):
        self._callbacks.registerHttpListener(self)
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self.logTable)
        self._callbacks.customizeUiComponent(self.scrollPane)
        self._callbacks.customizeUiComponent(self._bottomsplit)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.addSuiteTab(self)

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            requestMenuItem = JMenuItem("Send to SQL Detector")
            for response in responses:
                requestMenuItem.addActionListener(handleMenuItems(self, response, "request"))
            ret.add(requestMenuItem)
            return ret
        return None

    def getTabCaption(self):
        return "SQL Injection Detector"

    def getUiComponent(self):
        return self._splitpane

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 6

    def getColumnName(self, columnIndex):
        data = ['#', 'Method', 'URL', 'Parameters', 'SQL Status', 'Request Time']
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    def getColumnClass(self, columnIndex):
        data = [Integer, String, String, Integer, String, String]
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return rowIndex + 1
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._url.toString()
        if columnIndex == 3:
            return len(logEntry._parameter)
        if columnIndex == 4:
            return logEntry._SQLStatus
        if columnIndex == 5:
            return logEntry._req_time
        return ""

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInf):
        if self.intercept == 1:
            if toolFlag == self._callbacks.TOOL_PROXY:
                if not messageIsRequest:
                    requestInfo = self._helpers.analyzeRequest(messageInf)
                    requeststr = requestInfo.getUrl()
                    parameters = requestInfo.getParameters()
                    param_new = [p for p in parameters if p.getType() != 2]
                    if len(param_new) != 0:
                        if self._callbacks.isInScope(URL(str(requeststr))):
                            start_new_thread(self.sendRequestToSQLDetector, (messageInf,))

    def sendRequestToSQLDetector(self, messageInfo):
        if not self.sqlicheck.isSelected():
            return
            
        request = messageInfo.getRequest()
        req_time = datetime.datetime.today()
        requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
        
        # Get baseline timing
        baseline_response = self._callbacks.makeHttpRequest(
            self._helpers.buildHttpService(str(requestURL.getHost()), 
                                         int(requestURL.getPort()), 
                                         requestURL.getProtocol() == "https"), 
            request)
        baseline_time = datetime.datetime.today()
        baseline_duration = (baseline_time - req_time).total_seconds()
        
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        parameters = requestInfo.getParameters()
        requeststring = self._helpers.bytesToString(request)
        headers = requestInfo.getHeaders()
        

        param_new = [p for p in parameters if p.getType() == 0 or p.getType() == 1 or p.getType() == 6]
        
        SQLStatus = self.NOT_FOUND
        sql_results = []
        sql_descriptions = []
        sql_requests = []
        highest_score = 0

        for param in param_new:
            name = param.getName()
            ptype = param.getType()
            param_value = param.getValue()
            
            for payload in self.sql_payloads:
                score = 0
                description = ""
                

                if ptype == 0 or ptype == 1:  # GET or POST
                    new_parameter = self._helpers.buildParameter(name, payload, ptype)
                    updated_request = self._helpers.updateParameter(request, new_parameter)
                else:  # JSON
                    try:
                        jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
                        new = jsonreq.split(name + "\":", 1)[1]
                        if new.startswith('\"'):
                            newjsonreq = jsonreq.replace(name + "\":\"" + param_value, 
                                                       name + "\":\"" + payload)
                        else:
                            newjsonreq = jsonreq.replace(name + "\":" + param_value, 
                                                       name + "\":\"" + payload + "\"")
                        updated_request = self._helpers.buildHttpMessage(headers, newjsonreq)
                    except:
                        continue


                start_time = datetime.datetime.today()
                attack_response = self._callbacks.makeHttpRequest(
                    self._helpers.buildHttpService(str(requestURL.getHost()),
                                                 int(requestURL.getPort()),
                                                 requestURL.getProtocol() == "https"),
                    updated_request)
                end_time = datetime.datetime.today()
                
                if not attack_response.getResponse():
                    continue
                    
                response_time = (end_time - start_time).total_seconds()
                response_str = self._helpers.bytesToString(attack_response.getResponse())
                response_info = self._helpers.analyzeResponse(attack_response.getResponse())
                status_code = response_info.getStatusCode()
                

                if status_code == 500:
                    score += 2
                    description += "HTTP 500 Internal Server Error detected with payload. "
                

                found_errors = []
                for error_pattern in self.sql_errors:
                    if re.search(error_pattern, response_str, re.IGNORECASE):
                        found_errors.append(error_pattern)
                        score += 1
                
                if found_errors:
                    description += "SQL error patterns detected: " + ", ".join(found_errors[:3]) + ". "
                

                if "sleep" in payload.lower() and (response_time - baseline_duration) > 3:
                    score += 3
                    description += "Time-based SQL injection detected (response delayed by {:.2f} seconds). ".format(response_time - baseline_duration)
                

                if score > highest_score:
                    highest_score = score
                    best_description = description
                    best_request = attack_response
                    best_payload = payload


        if highest_score >= 3:
            SQLStatus = self.FOUND
        elif highest_score >= 2:
            SQLStatus = self.CHECK  
        elif highest_score == 1:
            SQLStatus = self.HTTP_500
        else:
            SQLStatus = self.NOT_FOUND


        self.addToLog(messageInfo, SQLStatus, param_new, best_description if highest_score > 0 else "", 
                      best_request if highest_score > 0 else None, req_time.strftime('%H:%M:%S %m/%d/%y'))

    def addToLog(self, messageInfo, SQLStatus, parameters, description, sql_request, req_time):
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        method = requestInfo.getMethod()
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(self._callbacks.saveBuffersToTempFiles(messageInfo), 
                              requestInfo.getUrl(), method, SQLStatus, req_time, 
                              parameters, description, sql_request))
        SwingUtilities.invokeLater(UpdateTableEDT(self, "insert", row, row))
        self._lock.release()

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.addMouseListener(mouseclick(self._extender))
        self.setRowSelectionAllowed(True)

    def prepareRenderer(self, renderer, row, col):
        comp = JTable.prepareRenderer(self, renderer, row, col)
        value = self._extender.getValueAt(self._extender.logTable.convertRowIndexToModel(row), col)

        if col == 4: 
            if value == self._extender.FOUND:
                comp.setBackground(Color(179, 0, 0))
                comp.setForeground(Color.WHITE)
            elif value == self._extender.CHECK:
                comp.setBackground(Color(255, 153, 51))
                comp.setForeground(Color.BLACK)
            elif value == self._extender.HTTP_500:
                comp.setBackground(Color(255, 255, 0))
                comp.setForeground(Color.BLACK)
            elif value == self._extender.NOT_FOUND:
                comp.setBackground(Color.LIGHT_GRAY)
                comp.setForeground(Color.BLACK)
        else:
            comp.setForeground(Color.BLACK)
            comp.setBackground(Color.LIGHT_GRAY)

        selectedRow = self._extender.logTable.getSelectedRow()
        if selectedRow == row:
            comp.setBackground(Color.WHITE)
            comp.setForeground(Color.BLACK)
        return comp

    def changeSelection(self, row, col, toggle, extend):
        if row >= 0:
            logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
            
            self._extender.textfield.setText("")
            url = logEntry._url.toString()
            
            if logEntry._SQLStatus != self._extender.NOT_FOUND:
                confidence = self.getConfidenceLevel(logEntry._SQLStatus)
                
                self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), 
                    "<h1>SQL Injection Detection</h1>", 0, 0, None)
                self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(),
                    "<br><table cellspacing=\"1\" cellpadding=\"0\">" +
                    "<tr><td>Issue:</td><td><b>SQL Injection</b></td></tr>" +
                    "<tr><td>Severity:</td><td><b>High</b></td></tr>" +
                    "<tr><td>Confidence:</td><td>" + confidence + "</td></tr>" +
                    "<tr><td>URL:</td><td><b>" + url + "</b></td></tr>" +
                    "</table>", 0, 0, None)
                self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(),
                    "<br><h3>Description</h3>", 0, 0, None)
                self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(),
                    logEntry._description, 0, 0, None)
                self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(),
                    "<br><h3>Remediation</h3>Use parameterized queries (prepared statements) " +
                    "to prevent SQL injection attacks.", 0, 0, None)
                self._extender.textfield.setCaretPosition(0)
                
                if logEntry._sql_request:
                    self._extender._requestViewer.setMessage(logEntry._sql_request.getRequest(), True)
                    self._extender._responseViewer.setMessage(logEntry._sql_request.getResponse(), False)
                    self._extender._currentlyDisplayedItem = logEntry._sql_request
                    self._extender._texteditor.setText(logEntry._sql_request.getResponse())

        JTable.changeSelection(self, row, col, toggle, extend)

    def getConfidenceLevel(self, status):
        if status == self._extender.FOUND:
            return "<b style=\"color:red;\">High</b>"
        elif status == self._extender.CHECK:
            return "<b style=\"color:orange;\">Medium</b>"
        elif status == self._extender.HTTP_500:
            return "<b style=\"color:orange;\">Low</b>"
        return "<b>None</b>"

class LogEntry:
    def __init__(self, requestResponse, url, method, SQLStatus, req_time, parameter, description, sql_request):
        self._requestResponse = requestResponse
        self._url = url
        self._method = method
        self._SQLStatus = SQLStatus
        self._req_time = req_time
        self._parameter = parameter
        self._description = description
        self._sql_request = sql_request

class mouseclick(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        pass

class autoScrollListener(AdjustmentListener):
    def __init__(self, extender):
        self._extender = extender

    def adjustmentValueChanged(self, e):
        if self._extender.autoScroll.isSelected():
            e.getAdjustable().setValue(e.getAdjustable().getMaximum())

class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        start_new_thread(self._extender.sendRequestToSQLDetector, (self._messageInfo,))

class UpdateTableEDT(Runnable):
    def __init__(self, extender, action, firstRow, lastRow):
        self._extender = extender
        self._action = action
        self._firstRow = firstRow
        self._lastRow = lastRow

    def run(self):
        if self._action == "insert":
            self._extender.fireTableRowsInserted(self._firstRow, self._lastRow)
        elif self._action == "update":
            self._extender.fireTableRowsUpdated(self._firstRow, self._lastRow)
        elif self._action == "delete":
            self._extender.fireTableRowsDeleted(self._firstRow, self._lastRow)