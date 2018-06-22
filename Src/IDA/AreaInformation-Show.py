import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'D:\Analysis\REPack\Src')
import pprint
import logging
import json

try:
    import IDA.Analysis
    import WinDBG.Command
except:
    pass

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

if __name__=='__main__':
    disasm=IDA.Analysis.Disasm()
    for (address, function_hash, sequence, type, value) in disasm.GetAreaInformation():
        print '%.8x: %s+%d %s %s' % (address, function_hash, sequence, type, value)

