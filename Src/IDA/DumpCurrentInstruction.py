import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'D:\Analysis\REPack\Src')
import pprint
import logging
import json

import IDA.Analysis
import WinDBG.Command

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

if __name__=='__main__':
    disasm=IDA.Analysis.Disasm()
    ea=disasm.GetSelectionStart()
    instruction=disasm.GetInstruction(ea)
    
    pprint.pprint(instruction)
    disasm.Exit()
