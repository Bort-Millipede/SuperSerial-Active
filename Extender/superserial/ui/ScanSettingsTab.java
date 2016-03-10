/*
	ScanSettingsTab.java
	
	v0.3 (3/10/2016)
	
	UI Component for the "Scan Settings" configuration tab under the SuperSerial tab. Allows the user to set settings related to the Active Scan checks performed by the 
	SuperSerial-Active extender (scan all parameters option, number of Node download attempts, time to wait between attempts). Also allows users to add new or edit/delete 
	existing operating commands used during an Active Scan.
*/

package superserial.ui;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.TableModelListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import java.awt.GridLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.Hashtable;

import burp.IBurpExtenderCallbacks;
import burp.PayloadCommandFactory;
import superserial.settings.SuperSerialSettings;

class ScanSettingsTab extends JPanel {
	//UI fields
	private JCheckBox scanAllField;
	private JTextField numAttemptsField;
	private JTextField waitTimeField;
	private JButton cmdUpButton;
	private JButton cmdDownButton;
	private JButton cmdAddButton;
	private JButton cmdRemoveButton;
	private JTable cmdTable;
	private CommandTableModel dtm;
	
	//data fields
	private SuperSerialSettings settings;
	private PayloadCommandFactory pcf;
	private IBurpExtenderCallbacks callbacks;

	ScanSettingsTab(IBurpExtenderCallbacks cb) {
		super(new GridLayout(4,2));
		
		settings = SuperSerialSettings.getInstance();
		pcf = PayloadCommandFactory.getInstance();
		callbacks = cb;
		
		add(new JLabel("Automatically test all parameters: (WARNING: This will significantly increase scan duration!):",SwingConstants.RIGHT));
		scanAllField = new JCheckBox((String) null,settings.getScanAll());
		scanAllField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JCheckBox jcb = (JCheckBox) ae.getSource();
				if(jcb.isSelected()) {
					if(JOptionPane.showConfirmDialog(null,"Are you sure you want to automatically test all parameters?\nThis will SIGNIFICANTLY increase active scan duration."+
								"\nOnly enable this setting if needed.","Confirm",JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE)==JOptionPane.YES_OPTION) {
						settings.setScanSettings(settings.getDownloadTries(),settings.getWaitTime(),true);
					} else {
						jcb.setSelected(false);
						settings.setScanSettings(settings.getDownloadTries(),settings.getWaitTime(),false);
					}
				} else {
					settings.setScanSettings(settings.getDownloadTries(),settings.getWaitTime(),false);
				}
			}
		});
		add(scanAllField);
		add(new JLabel("Number of download attempts:",SwingConstants.RIGHT));
		numAttemptsField = new JTextField(Integer.toString(settings.getDownloadTries()));
		numAttemptsField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent de) {
				changeAttempts();
			}
			public void insertUpdate(DocumentEvent de) {
				changeAttempts();
			}
			public void removeUpdate(DocumentEvent de) {
				changeAttempts();
			}
			public void changeAttempts() {
				try{
					settings.setScanSettings(Integer.parseInt(numAttemptsField.getText()),settings.getWaitTime(),settings.getScanAll());
				} catch(Exception e) {
					callbacks.issueAlert("Scan Settings: Invalid download attemps value!");
				}
			}
		});
		add(numAttemptsField);
		add(new JLabel("Milliseconds to wait between tries (1000 = 1 sec):",SwingConstants.RIGHT));
		waitTimeField = new JTextField(Integer.toString(settings.getWaitTime()));
		waitTimeField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent de) {
				changeTime();
			}
			public void insertUpdate(DocumentEvent de) {
				changeTime();
			}
			public void removeUpdate(DocumentEvent de) {
				changeTime();
			}
			public void changeTime() {
				try{
					settings.setScanSettings(settings.getDownloadTries(),Integer.parseInt(waitTimeField.getText()),settings.getScanAll());
				} catch(Exception e) {
					callbacks.issueAlert("Scan Settings: Invalid wait time value!");
				}
			}
		});
		add(waitTimeField);
		
		//create commands table
		Hashtable[] cmdHT = pcf.getCommandsArray();
		cmdTable = new JTable(new CommandTableModel());
		dtm = (CommandTableModel) cmdTable.getModel();
		dtm.addTableModelListener(new TableModelListener() {
			public void tableChanged(TableModelEvent tme) {
				switch(tme.getType()) {
					case TableModelEvent.UPDATE:
						int firstRow = tme.getFirstRow();
						int lastRow = tme.getLastRow();
						//callbacks.printError("UPDATE, first row:"+tme.getFirstRow()+", last row:"+tme.getLastRow()+", source: "+tme.getSource().toString());
						if(firstRow==lastRow) { //only one row updated (command editted)
							if(lastRow == dtm.getRowCount()-1) {
								String cmd = (String) dtm.getValueAt(lastRow,0);
								String os = (String) dtm.getValueAt(lastRow,1);
								boolean upload = (Boolean) dtm.getValueAt(lastRow,2);
								if(lastRow>=pcf.getCommandsCount()) { //add new command
									pcf.add(cmd,os,"web",upload);
								} else { //edit existing command
									pcf.edit(lastRow,cmd,os,"web",upload);
								}
							} else {
								String cmd = (String) dtm.getValueAt(lastRow,0);
								String os = (String) dtm.getValueAt(lastRow,1);
								boolean upload = (Boolean) dtm.getValueAt(lastRow,2);
								pcf.edit(lastRow,cmd,os,"web",upload);
							}
						}
						break;
				}
			}
		});
		
		//populate table with default built-in commands
		for(int i=0;i<cmdHT.length;i++) {
			Hashtable cmd = cmdHT[i];
			dtm.addRow(new Object[] {cmd.get("cmd"),cmd.get("os"),new Boolean(Boolean.parseBoolean((String) cmd.get("upload")))});
		}
		
		//create panel for buttons
		JPanel cmdButtonPanel = new JPanel(new GridLayout(4,1,0,2));
		cmdUpButton = new JButton("Move Selected Command Up");
		cmdDownButton = new JButton("Move Selected Command Down");
		cmdAddButton = new JButton("Add New Command");
		cmdRemoveButton = new JButton("Remove Selected Command(s)");
		ActionListener buttonAL = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JButton jb = (JButton) ae.getSource();
				String buttonText = jb.getText();
				int selectedCount = cmdTable.getSelectedRowCount();
				int[] selectedRows = cmdTable.getSelectedRows();
				int rowCount = cmdTable.getRowCount();
				
				if(buttonText.contains("Add")) { //add new command (if blank row is not already created)
					//check if last row command is blank
					String cmd = (String) dtm.getValueAt(rowCount-1,0);
					if(cmd!=null) cmd = cmd.trim();
					int select = rowCount;
					if((cmd!=null) && (!cmd.isEmpty())) { //if command is inputted
						dtm.addRow(new Object[] {"","Unknown",false});
					} else { //if command is blank
						select--;
					}
					cmdTable.setRowSelectionInterval(select,select);
					cmdTable.setColumnSelectionInterval(0,0);
				} else if(selectedRows.length!=0) { //if at least one row is selected
					if(buttonText.contains("Remove")) { //remove the selected rows; if 1 row is selected, selected the next row
						for(int i=(selectedRows.length-1);i>-1;i--) {
							pcf.remove(selectedRows[i]);
							dtm.removeRow(selectedRows[i]);
						}
						rowCount = cmdTable.getRowCount();
						if(selectedRows.length==1) { //only one row was selected/deleted
							if(rowCount>0) {
								int selected = selectedRows[0]-1;
								if(selectedRows[0]==rowCount) { //if last row was removed
									selected = rowCount-1;
								} else if(selectedRows[0]==0) { //if first row was removed
									selected = 0;
								}
								cmdTable.setRowSelectionInterval(selected,selected);
							}
						}
					} else if(selectedRows.length==1) { //if only 1 row is selected //POSSIBLE TODO: still move rows even if multiple (sequential) rows are selected
						if(buttonText.contains("Up")) { //if a row besides the top row or bottom row that contains a blank command is selected, move the selected row up one
							if(selectedRows[0]!=0) {
								boolean swap = true;
								if(selectedRows[0]==(rowCount-1)) {
									String cmd = (String) dtm.getValueAt(selectedRows[0],0);
									String os = (String) dtm.getValueAt(selectedRows[0],1);
									if(cmd!=null && os!=null) {
										if(cmd.isEmpty() || os.isEmpty()) {
											swap = false;
										}
									} else {
										swap = false;
									}
								}
								if(swap) {
									pcf.swap((String) dtm.getValueAt(selectedRows[0],0),(String) dtm.getValueAt(selectedRows[0]-1,0));
									dtm.moveRow(selectedRows[0],selectedRows[0],selectedRows[0]-1);
									cmdTable.setRowSelectionInterval(selectedRows[0]-1,selectedRows[0]-1);
								}
							}
						} else if(buttonText.contains("Down")) { //if a row besides the bottom row is selected, move the selected row down one
							if(selectedRows[0]!=rowCount-1) {
								pcf.swap((String) dtm.getValueAt(selectedRows[0],0),(String) dtm.getValueAt(selectedRows[0]+1,0));
								dtm.moveRow(selectedRows[0],selectedRows[0],selectedRows[0]+1);
								cmdTable.setRowSelectionInterval(selectedRows[0]+1,selectedRows[0]+1);
							}
						}
					}
				}
			}
		};
		cmdUpButton.addActionListener(buttonAL);
		cmdDownButton.addActionListener(buttonAL);
		cmdAddButton.addActionListener(buttonAL);
		cmdRemoveButton.addActionListener(buttonAL);
		cmdButtonPanel.add(cmdUpButton);
		cmdButtonPanel.add(cmdDownButton);
		cmdButtonPanel.add(cmdAddButton);
		cmdButtonPanel.add(cmdRemoveButton);
		
		add(cmdButtonPanel);
		add(new JScrollPane(cmdTable));
	}
	
	private class CommandTableModel extends DefaultTableModel {
		
		public CommandTableModel() {
			super(new String[] {"Command","OS","File Upload"},0);
		}
		
		@Override
		public Class<?> getColumnClass(int columnIndex) {
			Class c = String.class;
			switch(columnIndex) {
				case 2: c = Boolean.class;
			}
			return c;
		}
		
		@Override
		public boolean isCellEditable(int row, int column) {
			return true;
		}
	}
}
