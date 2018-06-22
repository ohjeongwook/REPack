import sys
import idaapi
import idautils
from idaapi import PluginForm
from PyQt5 import QtGui, QtCore, QtWidgets
import pprint
from TraceLoader import *
import IDA

class OperationForm_t(PluginForm):
	def PopulateTree(self):
		self.Tree.clear()
		
		ea=self.IDAUtil.GetFunctionAddress()
		current_root=self.AddItem(self.Tree,ea)

		ea_list=self.EnumerateTree(current_root,ea,0)
		for [ea,item,level] in ea_list:
			if level>4:
				continue
			ea_list+=self.EnumerateTree(item,ea,level+1)

		print 'PopulateTree finished'

	def EnumerateTree(self,current_root,parent,level):		
		address_list=[]
		for ea in self.IDAUtil.DumpFunctionCalls(parent):
			item=self.AddItem(current_root,ea)
			address_list.append([ea,item,level+1])
		return address_list

	def AddItem(self,current_root,ea):
		name=idaapi.get_true_name(int(ea),int(ea))
		print '%x: %s' % (ea,name)
		new_item=QtWidgets.QTreeWidgetItem(current_root)
		new_item.setText(0,"%s" % name)
		new_item.setText(1,"%x" % ea)
		
		return new_item

	def treeClicked(self,treeItem):
		if treeItem!=None:
			address=int(treeItem.text(1),16)
			print 'jumpto: %x' % (address)
			idaapi.jumpto(address)
			
	def OnCreate(self,form):
		self.IDAUtil=IDA.Util()
		self.ImageName=idaapi.get_root_filename()
		self.ImageBase=idaapi.get_imagebase()

		self.parent=self.FormToPyQtWidget(form)

		self.Tree=QtWidgets.QTreeWidget()
		self.Tree.setHeaderLabels(("Name","Address"))
		self.Tree.setColumnWidth(0,200)
		self.Tree.setColumnWidth(1,100)

		self.Tree.itemClicked.connect(self.treeClicked)
		
		layout=QtWidgets.QVBoxLayout()
		layout.addWidget(self.Tree)
		
		self.PopulateTree()
		self.parent.setLayout(layout)
		
	def OnClose(self,form):
		global OperationForm
		del OperationForm
		
	def Show(self):
		return PluginForm.Show(self, "IDA Tree", options=(PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))

def main():
	global OperationForm

	try:
		OperationForm
		OperationForm.OnClose(OperationForm)
		print ("reloading OperationForm")
		OperationForm=OperationForm_t()
		return	
	except:
		OperationForm=OperationForm_t()
		
	OperationForm.Show()

main()