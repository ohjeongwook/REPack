import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'D:\Analysis\REPack\Src')
import pprint
import logging
import IDA.Analysis
import WinDBG.Command

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

class Util:
    def __init__(self,ida_disasm=None):
        if ida_disasm!=None:
            self.IDADisasm=ida_disasm
        else:
            self.IDADisasm=IDA.Analysis.Disasm()

    def FindInstructions(self,range_str='',type=""):
        instructions=self.IDADisasm.GetInstructions(filter=self.IDADisasm.GetFilter(type))
        for instruction in instructions:
            print '%.8x\t%s' % (instruction['Address'], instruction['Disasm'])
            #pprint.pprint(instruction)

if __name__=='__main__':
    util=Util()
    util.FindInstructions("All","CallToDS")
