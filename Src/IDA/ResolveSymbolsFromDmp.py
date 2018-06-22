import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'C:\mat\Analysis\REPack\Src')

import pprint
import logging
import struct
import IDA.Analysis
import WinDBG.Command
import WinDBG.PyKD

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

class Util:
    def __init__(self,ida_disasm=None,filename=r''):
        if ida_disasm!=None:
            self.IDADisasm=ida_disasm
        else:
            self.IDADisasm=IDA.Analysis.Disasm()

        self.PykdTool=WinDBG.PyKD.Tool(dump_file=filename)
        self.PykdTool.SetSymbolPath()

    def FindAddrBytes(self,type=""):
        for addr in self.IDADisasm.Addresses(4):
            bytes=self.IDADisasm.DumpBytes(addr,4)
            if bytes!=None and len(bytes)==4:
                (dword,)=struct.unpack("<L", bytes)
                if dword>0:
                    symbol=self.PykdTool.ResolveSymbol(dword)
                    if symbol and symbol.find('+')<0:
                        self.IDADisasm.Redefine(addr,4,'data',data_type='DWORD')
                        self.IDADisasm.SetCmt(addr,symbol,1)
                        name=symbol.split('!')[1]
                        self.IDADisasm.SetName(addr,name)
                        print '%.8x %.8x %s' % (addr, dword, symbol)
            
if __name__=='__main__':
    import IDA.UI

    filename=r'D:\Analysis\Incidents\CCleaner\Samples\Shellcode\02\proc.dmp'
    
    if not os.path.isfile(filename):
        title='ResolveSymbol'
        try:
            form.OnClose(form)
            form=IDA.UI.Form(title)
        except:
            form=IDA.UI.Form(title)

        form.Show()

        filename=form.AskOpenFileName("DMP (*.dmp)")

    if filename:
        util=Util(filename=filename)
        util.FindAddrBytes()
