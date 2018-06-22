import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'D:\Analysis\REPack\Src')
import pprint
import logging
import json
import yara
import sqlite3
import base64
import copy

try:
    import IDA.Analysis
    import WinDBG.Command
except:
    pass

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

class Hunter:
    Debug=0
    def __init__(self,yara_file='',log_filename=''):
        self.Disasm=IDA.Analysis.Disasm(parse_args=False)
        self.Disasm.AddArgsOption("-y","--yara_filename",dest="yara_filename",type="string",default='',metavar="YARA_FILENAME",help="Yara filename")
        self.Disasm.AddArgsOption("-D","--db_filename",dest="db_filename",type="string",default='Matches.db',metavar="YARA_FILENAME",help="Match DB filename")
        self.Disasm.ParseArgs()

        if self.Disasm.Options.yara_filename:
            self.YaraRules=yara.compile(self.Disasm.Options.yara_filename)
        else:
            self.YaraRules=None
        self.OpenLog(log_filename)
        
        self.Matches={}

    def OpenLog(self,log_filename):
        if log_filename:
            self.fd=open(log_filename,'w')
        else:
            self.fd=None

    def WriteLog(self,line):
        if self.fd!=None:
            self.fd.write(line+'\n')
        else:
            print line

    def Close(self):
        if self.fd!=None:
            self.fd.close()
        self.Disasm.Exit()

    def FindLoops(self):
        for loop in self.Disasm.FindLoops():
            #print '%.8x: %s' % (loop['Function']['Address'], loop['Function']['Name'])
            for loop in loop['Loops']:
                print '\t', self.Disasm.DumpPaths(loop)
                block_instructions=[]
                for block_start in loop:
                    for instruction in self.Disasm.GetBlockInstructions(block_start):
                        print '\t\t', self.Disasm.GetInstructionText(instruction)
                        block_instructions.append(instruction)
                self.AddInstructions(block_instructions)
        
    def AddInstructions(self, block_instructions, max_call_instruction_cnt=0):
        call_instruction_cnt=0
        block_bytes=''
        for block_instruction in block_instructions:
            bytes=self.Disasm.GetInstructionBytes(block_instruction['Address'])
            block_instruction['Bytes']=base64.b64encode(bytes)
            block_bytes+=bytes
            if block_instruction['Op']=='call':
                call_instruction_cnt+=1

        yara_match_str=''
        if self.YaraRules!=None:
            yara_matches=self.YaraRules.match(data=block_bytes)
            
            for yara_match in yara_matches:
                yara_match_str+=str(yara_match)+' '
            
        if call_instruction_cnt>max_call_instruction_cnt and yara_match_str=='':
            return

        block_hash=self.Disasm.GetInstructionsHash(block_instructions)
        
        if not self.Matches.has_key(block_hash):
            self.Matches[block_hash]={}
        
        if not self.Matches[block_hash].has_key(yara_match_str):
            self.Matches[block_hash][yara_match_str]=[]
            
        self.Matches[block_hash][yara_match_str].append(block_instructions)
    
    def FindEncodingInstructions(self):
        min=0xffff
        black_list=[0x40000000, 0x4000, 0xffffffff, 0xFFFFFFF6, 0x0FFFFFFFE, 0xcccccccc, 0x400000, 0x80000000, 0x7FFFFFFF, 0x7EFEFEFF]

        self.Matches={}
        for instruction in self.Disasm.GetAllInstructions(filter={'Op': ['xor','add','mov','sub','imul','mul'], 'Target': 'Immediate'}):
            drefs=self.Disasm.GetDREFFrom(instruction['Address'])
            if len(drefs)==0:
                found_interesting_immediate_value=False
                for operand in instruction['Operands']:
                    if operand['Type']=='Immediate' and operand['Value']>min and not operand['Value'] in black_list:
                        found_interesting_immediate_value=True
                        break

                if found_interesting_immediate_value:
                    self.AddInstructions(self.Disasm.GetBlockInstructions(instruction['Address']))

    def Save(self, db_filename=''):
        if not db_filename:
            db_filename=self.Disasm.Options.db_filename
        
        try:
            conn = sqlite3.connect(db_filename)
        except:
            return
        conn.text_factory = str

        c = conn.cursor()

        create_table_sql = """CREATE TABLE
                            IF NOT EXISTS BlockInformation (
                                id integer PRIMARY KEY,
                                FileName text,
                                FileHash text,
                                FunctionName text,
                                BlockStart Integer,
                                BlockEnd Integer,
                                BlockHashType text,
                                BlockHash text,
                                YaraMatches text,
                                InstructionText text,
                                unique (FileName, FileHash, FunctionName, BlockStart, BlockEnd, BlockHashType, BlockHash, YaraMatches, InstructionText)
                            );"""

        c.execute(create_table_sql)

        file_name=self.Disasm.GetFileBasename()
        file_hash=self.Disasm.GetFileHash()

        for (block_hash,block_hash_items) in self.Matches.items():
            self.WriteLog('Block Hash: %s' % (block_hash))

            for (yara_match_str, block_instructions_list) in block_hash_items.items():
                self.WriteLog('\tYara Match: %s' % (yara_match_str))
                for block_instructions in block_instructions_list:
                    if len(block_instructions)==0:
                        continue

                    block_start=block_instructions[0]['Address']
                    block_end=block_instructions[-1]['Address']

                    function_name=self.Disasm.GetFunctioName(block_start)
                    self.WriteLog('\t\tFuction: %s' % (function_name))
                    
                    for block_instruction in block_instructions:
                        instruction_line=self.Disasm.GetInstructionText(block_instruction,include_bytes=True)+'\n'
                        self.WriteLog('\t\t\t%s' % instruction_line)

                    try:
                        c.execute('INSERT INTO BlockInformation (FileName, FileHash, FunctionName, BlockStart, BlockEnd, BlockHashType, BlockHash, YaraMatches, InstructionText) VALUES (?,?,?,?,?,?,?,?,?)',
                                (
                                    file_name, file_hash, function_name, block_start, 
                                    block_end, '', block_hash, yara_match_str, json.dumps(block_instructions)
                                )
                            )
                    except:
                        pass

        conn.commit()
        conn.close()
