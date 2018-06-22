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

    for (instruction, imm_operands) in disasm.FindImmediateSegmentsRefs():    
        print disasm.GetInstructionText(instruction)
        for imm_operand in imm_operands:
            print '\t%.8x' % imm_operand            
            drefs=disasm.GetDREFTo(imm_operand)
            for dref in drefs:
                print '\t\tdref: %.8x' % dref
                
            if len(drefs)==0:
                disasm.Redefine(imm_operand, 1, type='Data')
        disasm.Redefine(instruction['Address'], instruction['Size'], type='Code')

    disasm.Exit()