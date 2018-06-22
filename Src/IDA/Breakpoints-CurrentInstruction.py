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
import Breakpoints

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

if __name__=='__main__':
    breakpoints=Breakpoints.Util()
    breakpoints.AddCurrentInstruction()
    breakpoints.Save()
    breakpoints.Exit()