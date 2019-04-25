from collections import *
import pprint
import math
import json
import hashlib
import re
import copy
import logging
import sqlite3

from idaapi import *
from idautils import *
from idc import *
import idc
from optparse import OptionParser, Option

class Block:
    DebugLevel=0
    def __init__(self,addr=None):
        self.logger=logging.getLogger(__name__)
        self.IDAUtil=Util()
        if addr==None:
            self.Address=self.IDAUtil.GetSelectionStart()
        else:
            self.Address=addr
        self.Blocks=[]
        self.BlockRangeMap={}
        self.BlockInstructions={}
        self.CurrentBlock=self._GetBlockStart(self.Address)
        self._GetPrevBlockMap()

    def GetBlockBytes(self,ea):
        bytes=GetManyBytes(ea, self.BlockRangeMap[ea]-ea)
        return bytes

    def GetInstructionBytes(self,ea):
        if self.BlockInstructions.has_key(ea):
            instructions=self.BlockInstructions[ea]
            instructions.reverse()
            return instructions
        return []

    def _GetBlockStart(self,ea,prefix=''):
        start_ea=ea
        
        self.logger.debug(prefix+'_GetBlockStart: %x', ea)
        instructions=[]
        while 1:
            ea_size=get_item_size(ea)
            instructions.append((ea,GetManyBytes(ea,ea_size)))
            if self.IDAUtil.GetJMPCREFTo(ea)!=1:
                break

            if len(self.IDAUtil.GetJMPCREFFrom(prev_list[0]))!=1:
                break

            prev_ea=prev_list[0]
            ea=prev_ea
            
            self.logger.debug(prefix+'\t%x',ea)

        self.BlockRangeMap[ea]=start_ea+get_item_size(start_ea)
        instructions.reverse()
        self.BlockInstructions[ea]=instructions
        return ea

    def _GetPrevBlocks(self,bb,prefix=''):
        prev_bbs=[]
        
        self.logger.debug(prefix+'FindPrevBBs: %x',bb)
        for (cref_type,cref) in self.IDAUtil.GetCREFTo(bb):
            if cref_type!='Call':
                prev_bbs.append(self._GetBlockStart(prev_ea,prefix+'\t'))
            
        return prev_bbs

    def _GetPrevBlockMap(self):
        bb_list=[self.CurrentBlock]
        bb_map={self.CurrentBlock:1}
        self.RevMap={}
        self.Map={}
        for bb in bb_list:
            prev_bb_list=self._GetPrevBlocks(bb)
            self.RevMap[bb]=prev_bb_list
            for src in prev_bb_list:
                if not self.Map.has_key(src):
                    self.Map[src]=[]
                self.Map[src].append(bb)
            for prev_bb in prev_bb_list:                
                if not bb_map.has_key(prev_bb):
                    bb_list.append(prev_bb)
                    bb_map[prev_bb]=1

        self.Blocks=bb_map.keys()
        
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug('self.Blocks: %x',bb)
            for bb in self.Blocks:
                self.logger.debug('\t%x',bb)
            self.logger.debug('')

    def _TraverseBlock(self,block,map,blocks,level=0):
        prefix='\t'*level
        
        self.logger.debug(prefix+'%x',block)
        paths=[]
        blocks.append(block)
        if map.has_key(block):
            for prev_block in map[block]:
                if prev_block in blocks:
                    continue
                paths+=self._TraverseBlock(prev_block,map,copy.deepcopy(blocks),level+1)

        if len(paths)==0:
            paths.append(blocks)

        return paths

    def GetBlockPaths(self):
        blocks=[]
        paths=self._TraverseBlock(self.CurrentBlock,self.RevMap,blocks)
        return paths
        
    def GetBytes(self,blocks):
        bytes_list=[]
        for block in blocks:
            bytes_list.append((block,self.GetBlockBytes(block)))

        return bytes_list
    
    def DumpBlocks(self,blocks,sep=' '):
        line=''
        for block in blocks:
            if line!='':
                line+=sep
            line+='%x' % block
        return line
        
    def GetRootBlocks(self):
        roots=[]

        for target in self.RevMap.keys():
            self.logger.debug('target: %x',target)
            if len(self.RevMap[target])==0:
                roots.append(target)

            if self.logger.isEnabledFor(logging.DEBUG):
                for src in self.RevMap[target]:
                    self.logger.debug('\tsrc: %x (rev key: %d)',src,self.RevMap.has_key(src))

        if len(roots)>1:
            children={}
            for root in roots:
                for child in self.Map[root]:
                    children[child]=1
                    
            if len(children)==1:
                roots=children

        return roots

    def GetFuncName(self,demangle=True):    
        for root in self.GetRootBlocks():
            return self.IDAUtil.GetName(root,demangle=demangle)

class Disasm:
    Debug=0
    
    def __init__(self,parse_args=True):
        self.logger=logging.getLogger(__name__)
        self.ImageName=get_root_filename()
        self.ImageBase=get_imagebase()
        self.Parser=OptionParser(usage="usage: %prog [options] args")
        self.Parser.add_option("-x","--exit",dest="exit",action="store_true",default=False)
        self.Parser.add_option("-d","--db",dest="db",action="store_true",default=False)
        
        if parse_args:
            self.ParseArgs()

        self.WaitAnalysis()

    """ Data Type """

    """
    o_void     =  o_void      #  No Operand                           ----------
    o_reg      =  o_reg       #  General Register (al,ax,es,ds...)    reg
    o_mem      =  o_mem       #  Direct Memory Reference  (DATA)      addr
    o_phrase   =  o_phrase    #  Memory Ref [Base Reg + Index Reg]    phrase
    o_displ    =  o_displ     #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    o_imm      =  o_imm       #  Immediate Value                      value
    o_far      =  o_far       #  Immediate Far Address  (CODE)        addr
    o_near     =  o_near      #  Immediate Near Address (CODE)        addr
    """

    OperandTypes={}
    OperandTypes[o_void]="Void"
    OperandTypes[o_far]="Far"
    OperandTypes[o_near]="Near"
    OperandTypes[o_reg]="Register"
    OperandTypes[o_imm]="Immediate"                    
    OperandTypes[o_mem]="Memory"
    OperandTypes[o_displ]="Displacement"
    OperandTypes[o_phrase]="Phrase"
    
    """
    dt_byte = 0 #  8 bit
    dt_word = 1 #  16 bit
    dt_dword = 2 #  32 bit
    dt_float = 3 #  4 byte
    dt_double = 4 #  8 byte
    dt_tbyte = 5 #  variable size (ph.tbyte_size)
    dt_packreal = 6 #  packed real format for mc68040
    dt_qword = 7 #  64 bit
    dt_byte16 = 8 #  128 bit
    dt_code = 9 #  ptr to code (not used?)
    dt_void = 10 #  none
    dt_fword = 11 #  48 bit
    dt_bitfild = 12 #  bit field (mc680x0)
    dt_string = 13 #  pointer to asciiz string
    dt_unicode = 14 #  pointer to unicode string
    dt_3byte = 15 #  3-byte data
    dt_ldbl = 16 #  long double (which may be different from tbyte)
    dt_byte32 = 17 # 256 bit
    dt_byte64 = 18 # 512 bit
    """
    DTypeStr=["Byte", "Word", "DWORD", "Float", "Double",
              "TByte", "PackReal", "QWORD", "BYTE16", "CODE", 
              "Void", "FWORD", "BitFild", "String", "Unicode",
              "3Byte","LDBL","BYTE32","BYTE64"]

    def GetNativeSize(self):
        try:
            inf = get_inf_structure()
            if inf.is_32bit():
                return 32
            elif inf.is_64bit():
                return 64
            else:
                return 16
        except Exception as ex:
            raise RuntimeError("Can't determine native OS size: %s" % ex)

    def GetDtypSize(self,dtyp):
        if dtyp==dt_byte:
            return 1
        elif dtyp==dt_word:
            return 2            
        elif dtyp==dt_dword:
            return 4
        elif dtyp==dt_float:
            return 4
        elif dtyp==dt_double:
            return 8
        elif dtyp==dt_qword:
            return 8
        elif dtyp==dt_byte16:
            return 16            
        elif dtyp==dt_byte32:
            return 32
        elif dtyp==dt_byte64:
            return 64

    def MakeAddressInfo(self,rva,name):
        address_info={}
        address_info['RVA']=rva
        address_info['Address']=self.ImageBase+rva
        address_info['Type']="Function"
        address_info['Name']=name
        address_info['DumpTargets']=[]
        
        return address_info

    """ Name """    
    def GetName(self,ea,demangle=True):
        name=get_func_name(ea)
        demangled_name=idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        
        if demangled_name==None:
            return name
        else:
            return demangled_name

    def IsDefaultName(self,name):
        if name.startswith("sub_") or \
            name.startswith("loc_") or \
            name.startswith("locret_") or \
            name.startswith("dword_") or \
            name.startswith("word_") or \
            name.startswith("unknown_") or \
            name.startswith("unk_") or \
            name.startswith("off_"):
            return True
        return False

    def SetCmt(self,ea,cmt,flag=0):
        set_cmt(ea,str(cmt),flag)
    
    def SetName(self,ea,name):
        set_name(ea,str(name))

    def GetSegName(self,addr):
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            seg_name=get_segm_name(seg.startEA)
            if seg.startEA<=addr and addr<=seg.endEA:
                return seg_name
        return ''

    def InInSegment(self,addr):
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            seg_name=get_segm_name(seg)
            if seg.startEA<=addr and addr<=seg.endEA:
                return True
        return False

    def Addresses(self,interval=4):
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            addr=seg.startEA
            
            while addr<=seg.endEA:
                yield addr
                addr+=interval

    def FindName(self, name):
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            ea=seg.startEA
            while ea<seg.endEA:
                current_name=get_true_name(ea)
                
                if current_name!=None and current_name==name:
                    return ea

                ea+=get_item_size(ea)
        return None

    """ UI """
    def GetSelection(self):
        (selection,start,end) = read_selection()

        if selection:
            self.logger.debug("%d %x - %x", selection,start,end)
        else:
            start=get_screen_ea()
            end=start+1

        return (start,end)

    def GetSelectionStart(self):
        (ea,end) = self.GetSelection()
        return ea

    """REFs"""
    def GetItemSize(self,ea):
        return get_item_size(ea)

    def GetNext(self,ea):
        return ea+get_item_size(ea)

    def GetCREFFrom(self,ea):
        refs=[]
        ref=get_first_cref_from(ea)
        while ref!=BADADDR:           
            if ea+get_item_size(ea)==ref:
                refs.append(('Next',ref))
            else:
                decode_insn(ea)
                if cmd.get_canon_feature() & CF_CALL:
                    refs.append(('Call',ref))
                else:
                    refs.append(('Jmp',ref))

            ref=get_next_cref_from(ea,ref)
        return refs
        
    def GetJMPCREFFrom(self,ea):
        jmp_crefs=0
        for (cref_type, cref) in self.GetCREFFrom(ea):
            if cref_type=='Jmp':
                jmp_crefs.append(cref)
        return jmp_crefs

    def GetCREFTo(self,ea):
        refs=[]
        ref=get_first_cref_to(ea)
        while ref!=BADADDR:
            if ref+get_item_size(ref)==ea:
                refs.append(('Next',ref))
            else:
                decode_insn(ref)
                if cmd.get_canon_feature() & CF_CALL:
                    refs.append(('Call',ref))
                else:
                    refs.append(('Jmp',ref))
            ref=get_next_cref_to(ea,ref)

        return refs

    def GetJMPCREFTo(self,ea):
        jmp_crefs=0
        for (cref_type, cref) in self.GetCREFTo(ea):
            if cref_type=='Jmp':
                jmp_crefs.append(cref)
        return jmp_crefs

    def GetDREFFrom(self,ea):
        refs=[]
        ref=get_first_dref_from(ea)
        while ref!=BADADDR:
            refs.append(ref)
            ref=get_next_dref_from(ea,ref)
            
        return refs

    def GetDREFTo(self,ea):
        refs=[]
        ref=get_first_dref_to(ea)
        while ref!=BADADDR:
            refs.append(ref)
            ref=get_next_dref_to(ea,ref)
            
        return refs
        
    """Utility"""
    def DumpBytes(self,ea,length):
        return GetManyBytes(ea, length)

    def GetFilename(self):
        return get_input_file_path()
        
    def GetFileBasename(self):
        return os.path.basename(self.GetFilename())
        
    def GetFileHash(self):
        return GetInputFileMD5()

    """ Instruction level function """

    def GetRegName(self,reg,dtyp=None):
        if dtyp==None:
            return get_reg_name(reg,self.GetNativeSize()/8)
        else:
            return get_reg_name(reg,self.GetDtypSize(dtyp))

    def GetDisasmLine(self,ea):
        return tag_remove(generate_disasm_line(ea,0))

    def PrintOperandStructure(self,op):
        print "op.n: %x" % (op.n)
        print "op.type: %x" % (op.type)
        print "op.offb: %x" % (op.offb)
        print "op.flags: %x" % (op.flags)
        print "op.dtyp: %x" % (op.dtyp)
        print "op.reg: %s (%x)" % (self.GetRegName(op.reg),op.reg)
        print "op.phrase: %s (%x)" % (self.GetRegName(op.phrase),op.phrase)
        #print "op.value: %s (%x)" % (self.GetRegName(op.value),op.value)
        print "op.addr: %x" % (op.addr)
        print "op.specval: %x" % (op.specval)
        print "op.specflag1: %x" % (op.specflag1)
        print "op.specflag2: %x" % (op.specflag2)
        
        base  = op.specflag2 & 0x7
        index = (op.specflag2 & 0x38) >> 3
        scale = (op.specflag2 & 0xc0) >> 6
        
        if base!=5:
            print "\tbase: %s (%x)" % (self.GetRegName(base),base)
            
        if index!=4:
            print "\tindex: %s (%x)" % (self.GetRegName(index),index)

        print "\tscale: %x" % scale
        
        print "op.specflag3: %x" % (op.specflag3)
        print "op.specflag4: %x" % (op.specflag4)
        print ''

    def GetOperand(self,operand):
        operand_repr=None

        if operand.type!=o_void:
            if self.Debug>3 and self.logger.isEnabledFor(logging.DEBUG):
                self.PrintOperandStructure(op)
        
            operand_repr={}
            operand_repr['DataType']=self.DTypeStr[operand.dtyp]
            if self.OperandTypes.has_key(operand.type):
                operand_repr['Type']=self.OperandTypes[operand.type]
            else:
                operand_repr['Type']='%x' % operand.type

            operand_repr['TypeValue']=operand.type

            if operand.type==o_far:
                operand_repr['Value']=operand.addr

            elif operand.type==o_near:
                operand_repr['Value']=operand.addr

            elif operand.type == o_reg:
                operand_repr['Value']=self.GetRegName(operand.reg,operand.dtyp)

            elif operand.type == o_imm:
                operand_repr['Value']=operand.value

            else:
                base_reg=''
                index_reg=''
                scale=0
                if operand.specflag1:
                    base  = operand.specflag2 & 0x7
                    index = (operand.specflag2 & 0x38) >> 3
                    scale = (operand.specflag2 & 0xc0) >> 6

                    if base!=5 or operand.type != o_mem:
                        base_reg=self.GetRegName(base)
                        
                    if index!=4:
                        index_reg=self.GetRegName(index)
                else:
                    if operand.phrase!=5 or operand.type != o_mem:
                        base_reg=self.GetRegName(operand.phrase)

                operand_repr['Base']=base_reg
                operand_repr['Scale']=int(math.pow(2,scale))
                operand_repr['Index']=index_reg

                if operand.type == o_mem:
                    operand_repr['Address']=operand.addr
                    operand_repr['Segment']=self.GetSegName(operand.addr)

                elif operand.type == o_displ:            
                    operand_repr['Offset']=operand.addr

        return operand_repr
        
    def GetOperandStr(self,operand):
        operand_str=''
        if operand['Type']=="Void":
            pass
        elif operand['Type']=="Far" or \
             operand['Type']=="Near":
            operand_str=operand['Value']

        elif operand['Type']=="Register":
            operand_str=operand['Value']

        elif operand['Type']=="Immediate" or \
             operand['Type']=="Memory":
            operand_str=operand['Value']

        elif operand['Type']=="Displacement":
            index_str=''
            if operand['Index']:
                index_str='+%s' % operand['Index']

            if operand['Scale']==1:
                operand_str='%s%s+%d' % (operand['Base'], index_str, operand['Offset'])
            else:
                operand_str='%s*%s%s+%d' % (operand['Base'], operand['Scale'], index_str, operand['Index'])

        elif operand['Type']=="Phrase":
            operand_str=''
            
        return operand_str

    def GetFilter(self,type):
        if type=="CallToDS":
            filter={'Op': ['call'], 'Target': 'Section'}
        elif type=="IndirectCall":
            filter={'Op': ['call', 'jmp'], 'Target': 'Indirect'}
        elif type=='Pointer':
            filter={'Op': ['mov'], 'Target': 'Pointer'}
        elif type=='DisplacementCall':
            filter={'Op': ['call'], 'Target': 'Displacement'}
        else:
            filter={}
        return filter

    def MatchInstructionFilter(self,filter,instruction):
        if filter!=None:
            if filter.has_key('Op'):
                if not instruction['Op'] in filter['Op']:
                    return False

            if filter.has_key('Target'):
                matched=False
                if filter['Target']=='Displacement':
                    for operand in instruction['Operands']:
                        if operand['Type']=='Displacement':
                            matched=True

                elif filter['Target']=='Immediate':
                    for operand in instruction['Operands']:
                        if operand['Type']=='Immediate':
                            matched=True                            

                elif filter['Target']=='Pointer':
                    for operand in instruction['Operands']:
                        if operand['Type']=='Displacement':
                            if operand['Base']!='esp' and operand['Base']!='ebp':
                                matched=True

                elif filter['Target']=='Indirect':
                    operand_type=instruction['Operands'][0]['Type']
                    if operand_type=='Register':
                        matched=True
                    elif operand_type=='Memory':
                        if instruction['Operands'][0]['Segment']!='_idata':
                            matched=True
                    elif operand_type=='Displacement':
                        matched=True

                elif filter['Target']=='Section':
                    operand_type=instruction['Operands'][0]['Type']
                    if operand_type=='Memory':
                        matched=True

                if not matched:
                    return False
        return True

    def GetInstructionBytes(self,ea):
        return GetManyBytes(ea, ItemSize(ea))        

    def GetInstruction(self,current,filter=None):
        #if not isCode(GetFlags(current)):
        #    return None

        instruction={}
        instruction['Type']="Instruction"
        instruction['RVA']=current-self.ImageBase
        instruction['Address']=current
        instruction['Size']=get_item_size(current)        
        instruction['Disasm']=self.GetDisasmLine(current)
        op=GetMnem(current)
        instruction['Op']=op
        instruction['DREFFrom']=self.GetDREFFrom(current)
        instruction['CREFFrom']=self.GetCREFFrom(current)
        
        feature=cmd.get_canon_feature()
        instruction['IsCall']=(feature & CF_CALL)

        instruction['IsIndirectRegCall']=False
        if op=='call' or op=='jmp':
            operand=cmd.Operands[0]

            is_reg_call=False
            if operand.type in (o_reg, o_mem, o_displ, o_phrase):
                is_reg_call=True

            if is_reg_call:
                operand_str=GetOpnd(current,0)
                if operand_str.find('cs:')>=0 or operand_str.find('ds:')>=0:
                    is_reg_call=False

            if is_reg_call:
                if self.Debug>2:
                    self.logger.debug('%x %s %s (%s)', current, op, operand_str, self.OperandTypes[operand.type])
                instruction['IsIndirectRegCall']=True

        use_flags=[CF_USE1,CF_USE2,CF_USE3,CF_USE4,CF_USE5,CF_USE6]
        chg_flags=[CF_CHG1,CF_CHG2,CF_CHG3,CF_CHG4,CF_CHG5,CF_CHG6]

        instruction['Operands']=[]
        for i in range(0,6,1):
            operand = cmd.Operands[i]
            if not operand:
                break

            operand_repr =self.GetOperand(operand)
            if operand_repr==None:
                break

            if feature & use_flags[i]:
                operand_repr["Use"]=True

            if feature & chg_flags[i]:
                operand_repr["Chg"]=True

            operand_repr['Position']=i
            instruction['Operands'].append(operand_repr)
        
        name=get_true_name(current)
        if name!=None and name and not self.IsDefaultName(name):
            instruction['Name']=name
        else:
            instruction['Name']=''

        cmt=get_cmt(current,0)
        if cmt!=None and cmt:
            instruction['Comment']=cmt
        else:
            instruction['Comment']=''

        repeatable_cmt=get_cmt(current,1)
        if repeatable_cmt!=None and repeatable_cmt:
            instruction['Repeatable Comment']=repeatable_cmt
        else:
            instruction['Repeatable Comment']=''

        if self.MatchInstructionFilter(filter,instruction):
            return instruction

        return None

    def GetInstructionText(self,instruction,include_bytes=False,bytes_width=10):
        if instruction['Comment']:
            cmt=instruction['Comment']
        else:
            cmt=''

        cmt+=instruction['Repeatable Comment']
        
        if cmt:
            cmt='; '+cmt

        bytes_str=''
        if include_bytes:
            for byte in self.GetInstructionBytes(instruction['Address']):
                bytes_str+='%.2x ' % ord(byte)

        if len(bytes_str) < 3*bytes_width:
            bytes_str+=' ' * (3*bytes_width-len(bytes_str))

        line='%.8x (+%.8x) %s\t%s%s' % (
                        instruction['Address'],
                        instruction['RVA'],
                        bytes_str,
                        instruction['Disasm'],
                        cmt
                    )

        return line
        
    def GetCmt(self,current):
        full_cmt=''

        cmt=get_cmt(current,0)
        if cmt!=None and cmt:
            full_cmt+=cmt

        repeatable_cmt=get_cmt(current,1)
        if repeatable_cmt!=None and repeatable_cmt:
            full_cmt+=repeatable_cmt
        return full_cmt

    def GetInstructionsByRange(self,start=None,end=None,filter=None):
        if start==None or end==None:
            (start,end)=self.GetSelection()

        instructions=[]
        current=start
        while current<end:
            if isCode(GetFlags(current)):
                instruction=self.GetInstruction(current,filter=filter)
                if instruction!=None:
                    instructions.append()
            current+=get_item_size(current)
        return instructions

    def GetInstructions(self,filter=None):
        instructions=[]
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            current=seg.startEA
            while current<seg.endEA:        
                if isCode(GetFlags(current)):
                    instruction=self.GetInstruction(current,filter=filter)
                    if instruction!=None:
                        instructions.append(instruction)
                current+=get_item_size(current)
        return instructions

    def FindREPatterns(self,pattern,search_all=False,ea=None):
        matches=[]
        re_pattern=re.compile(pattern, re.IGNORECASE)

        if search_all:
            for i in range(0,get_segm_qty(),1):
                seg=getnseg(i)
                current=seg.startEA
                while current<seg.endEA:
                    disasm_line=self.GetDisasmLine(current)
                    try:
                        m=re_pattern.match(disasm_line)
                        if m:
                            self.logger.debug('%x: %s',current, disasm_line)
                            matches.append([current,disasm_line])
                    except:
                        pass                    
                    current+=get_item_size(current)
        else:
            if ea==None:
                ea=self.GetFunctionAddress()

            func=get_func(ea)

            checked_eas={func.startEA:1}
            start_ea_list=[func.startEA]

            for current in start_ea_list:
                if self.Debug>3:
                    self.logger.debug('* Basic Block: %x',current)

                while 1:
                    if isCode(GetFlags(current)):
                        inslen = decode_insn(current)
                        if inslen==0:
                            break

                        op=GetMnem(current)
                        disasm_line=self.GetDisasmLine(current)

                        try:
                            m=re_pattern.match(disasm_line)
                            if m:
                                self.logger.debug('%x: %s',current, disasm_line)
                                matches.append([current,disasm_line])
                        except:
                            pass
                        
                        if op.startswith('ret'):
                            break

                        feature=cmd.get_canon_feature()
                        is_call=feature & CF_CALL
                        
                        if not is_call:                        
                            found_non_next_addr=False
                            for cref in crefs:
                                if cref==next_addr:
                                    continue

                                found_non_next_addr=True

                                self.logger.debug('\t%x',cref)

                                if not checked_eas.has_key(cref):
                                    checked_eas[cref]=1
                                    start_ea_list.append(cref)
                            if found_non_next_addr:
                                break

                    else:
                        break
                    current+=get_item_size(current)

        return matches

    """ Function level function """
    def GetFunctions(self):
        functions=[]
        for i in range(0,get_func_qty(),1):
            function=getn_func(i)

            funcion_ea=function.startEA
            function_name=GetFunctionName(funcion_ea)
            function_args=self.GetStackArgs(funcion_ea)
            functions.append(
                {
                    'Type': "Function",
                    'Address': funcion_ea,
                    'RVA': funcion_ea-self.ImageBase,
                    'Name': function_name,
                    'Args': function_args
                }
            )
        
        return functions

    def GetFunctionAddress(self,ea=None):
        if ea==None:
            ea=self.GetSelectionStart()

        func=get_func(ea)

        if func:
            return func.startEA
        else:
            return -1

    def GetStackArgs(self,ea):
        stack=GetFrame(ea)
        args=[]
        return_address_passed=False
        last_name=''
        return_offset=0
        for offset in xrange(GetStrucSize(stack)):
            name=GetMemberName(stack, offset)
            if name and name!=last_name:
                if return_address_passed:
                    arg_offset=offset-return_offset
                    args.append((name,arg_offset))
                elif name==' r':
                    return_address_passed=True
                    return_offset=offset

                last_name=name

        return args

    def FuncionInstructions(self,ea=None,filter=None,type='Instruction'):
        if ea==None:
            ea=self.GetSelectionStart()

        func=get_func(ea)
        if func:
            ea=func.startEA
            
        instructions=[]
        block_starts={}
        block_ends={}

        block_start_map={func.startEA:1}
        block_start_list=[func.startEA]
        crefs_map={}
        for block_start in block_start_list:
            current=block_start
            while 1:
                instruction=self.GetInstruction(current)
                if instruction==None:
                    break
                    
                if self.MatchInstructionFilter(filter,instruction):                        
                    if type=='Instruction':
                        yield instruction
                    instructions.append(instruction)

                if instruction['Op'].startswith('ret'):
                    break

                found_jmp=False
                crefs_map[current]=[]
                for (cref_type,cref) in instruction['CREFFrom']:
                    if cref_type=='Jmp':
                        found_jmp=True

                    if type=='Map' and cref_type!='Call':
                        crefs_map[current].append(cref)

                if found_jmp:
                    for (cref_type,cref) in instruction['CREFFrom']:
                        if cref_type!='Call':
                            if not block_starts.has_key(cref):
                                if self.Debug>1:
                                    self.logger.debug("Found basic block: %.8x" % cref)

                                block_starts[cref]=1
                                block_start_list.append(cref)

                            if cref_type=='Jmp':
                                block_starts[cref]=1
                    break

                current+=get_item_size(current)

            if type=='Block':
                block_starts[block_start]=1
                block_ends[current]=1

        if type=='Block' or type=='Map':
            current_block_instructions=[]
            last_block_start=0
            for instruction in instructions:               
                if block_starts.has_key(instruction['Address']) and len(current_block_instructions)>0:
                    block_start=current_block_instructions[0]['Address']
                    block_end=current_block_instructions[-1]['Address']
                    
                    if type=='Map':
                        if crefs_map.has_key(block_end):
                            for dst in crefs_map[block_end]:
                                yield (block_start, block_end, dst)

                    elif type=='Block':
                        yield (
                                block_start,
                                block_end,
                                current_block_instructions
                              )
                    current_block_instructions=[]
                    
                    last_block_start=block_start

                current_block_instructions.append(instruction)
                if block_ends.has_key(instruction['Address']):
                    block_start=current_block_instructions[0]['Address']
                    block_end=current_block_instructions[-1]['Address']

                    if type=='Map':
                        if crefs_map.has_key(block_end):
                            for dst in crefs_map[block_end]:
                                yield (block_start, block_end, dst)

                    elif type=='Block':
                        yield (
                                block_start,
                                block_end,
                                current_block_instructions
                              )
                    current_block_instructions=[]
                    last_block_start=block_start

            if len(current_block_instructions)>0:
                block_start=current_block_instructions[0]['Address']
                block_end=current_block_instructions[-1]['Address']
                if type=='Map':
                    if crefs_map.has_key(block_end):
                        for dst in crefs_map[block_end]:
                            yield (block_start, block_end, dst)

                elif type=='Block':
                    yield (
                            block_start,
                            block_end,
                            current_block_instructions
                          )

    def GetJmpAddress(self,instruction):
        if not instruction.has_key('CREFFrom'):
            return 0

        for (cref_type,cref) in instruction['CREFFrom']:
            if cref_type=='Jmp':
                return cref
        return 0
        
    def GetFunctionInstructions(self,ea=None,filter=None):
        instructions=[]
        for instruction in self.FuncionInstructions(ea,filter=filter):
            instructions.append(instruction)
        return instructions
        
    def GetFunctionBlocks(self,ea=None,filter=None):
        blocks=[]
        for (block_start,block_end,instructions) in self.FuncionInstructions(ea,filter=filter,type='Block'):
            blocks.append((block_start,block_end,instructions))
        return blocks

    def GetFunctionMap(self,ea=None):
        instructions=[]
        src_map={}
        dst_map={}
        for (src,src_end, dst) in self.FuncionInstructions(ea,type='Map'):
            if not src_map.has_key(src):
                src_map[src]=[]

            src_map[src].append(dst)

            if not dst_map.has_key(dst):
                dst_map[dst]=[]
            dst_map[dst].append(src)
            
        return (src_map, dst_map)

    def GetBlockInstructions(self,ea=None,filter=None):
        for (block_start,block_end,instructions) in self.FuncionInstructions(ea,filter=filter,type='Block'):
            if block_start<=ea and ea<=block_end:
                return instructions
        return []

    def GetFunctionCallRefs(self,ea=None,filter=None):
        indirect_reg_call_refs=[]
        call_refs=[]
        instructions=[]

        for instruction in self.FuncionInstructions(ea,filter=filter):
            if instruction['IsIndirectRegCall']:
                indirect_reg_call_refs.append((instruction['Address'],instruction['Operands']))

            for (cref_type,cref) in instruction['CREFFrom']:
                if cref_type=='Call':
                    call_refs.append((instruction['Address'],cref))                   

            if self.MatchInstructionFilter(filter,instruction):
                instructions.append(instruction)

        return (call_refs,indirect_reg_call_refs,instructions)

    def GetFunctionRefs(self,ea=None):
        if ea==None:
            ea=self.GetSelectionStart()

        func=get_func(ea)

        if not func:
            return []

        checked_eas={func.startEA:1}
        start_ea_list=[[func.startEA,0],]

        crefs_map=defaultdict(list)
        back_crefs_map=defaultdict(list)
        i=0
        for [current,end] in start_ea_list:
            if self.Debug>3:
                self.logger.debug('* Basic Block: %x',current)

            current_block_start=current
            while 1:
                next_addr=current+get_item_size(current)
                if isCode(GetFlags(current)):
                    inslen = decode_insn(current)
                    if inslen==0:
                        break

                    op=GetMnem(current)
                    
                    if self.logger.isEnabledFor(logging.DEBUG):
                        disasm_line=self.GetDisasmLine(current)
                        self.logger.debug('%x: %s',current, disasm_line)

                    if op.startswith('ret'):
                        break

                    feature=cmd.get_canon_feature()
                    
                    if not (feature & CF_CALL):
                        found_non_next_addr=False
                        for (cref_type,cref) in self.GetCREFFrom(current):
                            if cref_type=='Next':
                                continue

                            found_non_next_addr=True
                            crefs_map[current_block_start].append(cref)
                            back_crefs_map[cref].append(current_block_start)
                            self.logger.debug('\t%x',cref)

                            if not checked_eas.has_key(cref):
                                checked_eas[cref]=1
                                start_ea_list.append([cref,0])
                                
                        if found_non_next_addr:
                            break

                else:
                    break
                current=next_addr

            if start_ea_list[i][1]==0:
                start_ea_list[i][1]=current+get_item_size(current)
            i+=1
                
        return (start_ea_list,crefs_map,back_crefs_map)

    def GetFunctioName(self,ea):
        return get_func_name(ea)

    def GetInstructionsHash(self,instructions,hash_types=['Op','imm_operand']):
        op_string=''
        for instruction in instructions:
            if 'Op' in hash_types:
                op_string+=instruction['Op']

            if len(instruction['DREFFrom'])==0:
                for operand in instruction['Operands']:
                    if 'imm_operand' in hash_types and operand['TypeValue']==o_imm:
                        op_string+=('%x' % operand['Value'])

        m=hashlib.sha1()
        m.update(op_string)
        return m.hexdigest()

    def GetAllInstructions(self,filter=None):
        instructions=[]
        for i in range(0,get_func_qty(),1):
            func=getn_func(i)

            for instruction in self.GetFunctionInstructions(func.startEA,filter):
                instructions.append(instruction)
        return instructions

    def FindImmediateSegmentsRefs(self):
        instructions=[]
        for instruction in self.GetAllInstructions(filter={'Target': 'Immediate'}):
            imm_operands=[]
            for operand in instruction['Operands']:
                if operand['Type']=='Immediate' and self.InInSegment(operand['Value']):
                    imm_operands.append(operand['Value'])
                    
            if len(imm_operands)>0:
                instructions.append((instruction, imm_operands))

        return instructions
        
    def DumpPaths(self,paths):
        path_str=''
        for path in paths:
            path_str+='%.8x ' % path

        return path_str
    
    def EnumeratePaths(self, src_map, src, visited_nodes={}, paths=[], loops={}):
        index=0
        for path in paths:
            if path==src:
                break
            index+=1

        if visited_nodes.has_key(src):
            return

        if index!=len(paths):
            loops[str(paths[index:])]=paths[index:]
            return

        if self.Debug>0:
            print self.DumpPaths(paths + [src])
        
        if src_map.has_key(src):
            visited_nodes=copy.deepcopy(visited_nodes)

            for dst in src_map[src]:
                self.EnumeratePaths(src_map, dst, visited_nodes, paths + [src], loops)
                visited_nodes[dst]=1
        return loops.values()

    def FindFunctionLoops(self,ea=None):
        (src_map, dst_map)=self.GetFunctionMap(ea)

        roots=[]
        for src in src_map.keys():
            if not dst_map.has_key(src):
                if self.Debug>0:
                    print 'Root: %.8x' % src
                roots.append(src)

        if self.Debug>0:
            for (src, dst_list) in src_map.items():
                for dst in dst_list:
                    print 'Dump: %.8x -> %.8x' % (src, dst)

        loops=[]
        for root in roots:
            loops+=self.EnumeratePaths(src_map, root, {}, [], {})

        return loops

    def FindLoops(self):
        loops_list=[]
        for function in self.GetFunctions():
            loops=self.FindFunctionLoops(function['Address'])
            
            if len(loops)>0:
                loops_list.append(
                    {
                        'Function': function,
                        'Loops': loops
                    }
                )

        return loops_list

    def GetInstructionNotations(self,hash_types=['Op','imm_operand']):
        function_notes=[]
        checked_ea={}
        for i in range(0,get_func_qty(),1):
            func=getn_func(i)

            instructions=[]
            for instruction in self.GetFunctionInstructions(func.startEA):
                instructions.append(instruction)

            function_hash=self.GetInstructionsHash(instructions,hash_types)

            self.logger.debug('* %s' % (function_hash))
            sequence=0
            for instruction in instructions:
                checked_ea[instruction['Address']]=1
                address=instruction['Address']
                if instruction['Name']:
                    self.logger.debug('* \t+%.3x Name: %s' % (sequence, instruction['Name']))
                    function_notes.append((address, function_hash, sequence, 'Name', instruction['Name']))

                if instruction['Comment']:
                    self.logger.debug('* \t+%.3x Comment: %s' % (sequence, instruction['Comment']))
                    function_notes.append((address, function_hash, sequence, 'Comment', instruction['Comment']))

                if instruction['Repeatable Comment']:
                    self.logger.debug('* \t+%.3x Repeatable Comment: %s' % (sequence, instruction['Repeatable Comment']))
                    function_notes.append((address, function_hash, sequence, 'Repeatable Comment', instruction['Repeatable Comment']))
                sequence+=1

        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            ea=seg.startEA
            while ea<seg.endEA:
                if not checked_ea.has_key(ea):
                    instruction=self.GetInstruction(ea)                    
                    if instruction!=None:
                        name=instruction['Name']
                        comment=instruction['Comment']
                        repeatable_comment=instruction['Repeatable Comment']
                    else:
                        name=self.GetName(ea)
                        comment=self.GetCmt(ea)
                        repeatable_comment=''
                        
                    if name or comment or repeatable_comment:
                        function_notes.append((ea,'',0,'Name', name)) 
                        function_notes.append((ea,'',0,'Comment', comment)) 
                        function_notes.append((ea,'',0,'Repeatable Comment', repeatable_comment)) 
                ea+=get_item_size(ea)
        return function_notes

    def SaveInstructionNotations(self, filename='AreaInformation.db'):        
        try:
            conn = sqlite3.connect(filename)
        except:
            return

        c = conn.cursor()

        create_table_sql = """CREATE TABLE
                            IF NOT EXISTS AreaInformation (
                                id integer PRIMARY KEY,
                                Address text,
                                HashType text NOT NULL,
                                HashParam text,
                                Hash text,
                                Sequence integer,
                                Type text,
                                Value text,
                                unique (Address, HashType, HashParam, Hash, Sequence, Type, Value)
                            );"""

        c.execute(create_table_sql)

        for (address, function_hash, sequence, type, value) in self.GetInstructionNotations():
            try:
                c.execute('INSERT INTO AreaInformation (Address, HashType, HashParam, Hash, Sequence, Type, Value) VALUES (?,?,?,?,?,?,?)',
                    (str(address), 'FunctionHash', '', function_hash, sequence, type, value))
            except:
                print 'address:', address
                print 'function_hash:', function_hash
                print 'sequence:', sequence
                print 'type:', type
                print 'value:', value

        conn.commit()
        conn.close()
        
    def LoadInstructionNotations(self, filename='AreaInformation.db',hash_types=['Op','imm_operand']):        
        try:
            conn = sqlite3.connect(filename)
        except:
            return

        c = conn.cursor()
        
        information={}
        for (id, address, hash_type, hash_param, hash, seq, type, value) in c.execute('SELECT * FROM AreaInformation'):
            address = int(address)
            information[address]=[type, value]

        for i in range(0,get_func_qty(),1):
            func=getn_func(i)

            instructions=[]
            for instruction in self.GetFunctionInstructions(func.startEA):
                instructions.append(instruction)

            function_hash=self.GetInstructionsHash(instructions,hash_types)
            
            if information.has_key(function_hash):
                [type, value]=information[function_hash]
                address = func.startEA
              
                if type=='Comment':
                    self.SetCmt(address, value)
                if type=='Repeatable Comment':
                    self.SetCmt(address, value, 1)
                if type=='Name':
                    self.SetName(address, value)
        
    def GenHash2Name(self,entries,hash_type_filter):
        hash_2_name={}
        for entry in entries:
            if not entry.has_key('Name') or not entry.has_key('Hash'):
                continue

            hash_type=entry['Hash']['Type']
            if hash_type!=hash_type_filter:
                continue

            hash=entry['Hash']['Value']
            if not hash_2_name.has_key(hash):
                hash_2_name[hash]=[]
            hash_2_name[hash].append(entry)
            
        for (k,v) in hash_2_name.items():
            if len(v)>1:
                del hash_2_name[k]
            else:
                hash_2_name[k]=v[0]

        return hash_2_name

    def LoadFunctionNameByHashes(self,filename):
        fd=open(filename,'r')
        data=json.loads(fd.read())
        fd.close()

        hash_type_filter=['Op','imm_operand']
        hash_2_name=self.GenHash2Name(data['Function Hashes'],hash_type_filter)
        current_hash_2_name=self.GenHash2Name(self.GetFunctionHashes(),hash_type_filter)

        function_matches={}
        for (k,v) in current_hash_2_name.items():
            if hash_2_name.has_key(k):
                current_entry=current_hash_2_name[k]
                import_entry=hash_2_name[k]

                current_ea=current_entry['Address']                
                current_name=current_entry['Name']
                import_ea=import_entry['Address']
                import_name=import_entry['Name']

                if import_name.startswith("sub_"):
                    import_name="_"+import_name

                self.logger.debug('%x: %s -> %s',current_ea,current_name,import_name)
                function_matches[import_ea]=current_ea
                set_name(int(current_ea),str(import_name))

        names_and_comments=data['Names and Comments']
        for address_str in names_and_comments.keys():
            address=int(address_str,10)
            function_address=names_and_comments[address_str]['Function']

            if function_matches.has_key(function_address):
                current_function_address=function_matches[function_address]
                current_address=current_function_address+address-function_address

                self.logger.debug('> %x (function: %x)', current_address, current_function_address)
                for data_type in names_and_comments[address_str].keys():
                    if data_type=='Function':
                        continue

                    value=names_and_comments[address_str][data_type]

                    if self.IsDefaultName(value):
                        continue

                    self.logger.debug('\t%x: %s %s (orig address=%x/function=%x (diff=%x))', current_address,data_type,value, address,function_address,address-function_address)
                    if data_type=='Name':
                        set_name(current_address,str(value))

                    elif data_type=='Comment':
                        set_cmt(current_address,str(value),0)

                    elif data_type=='Repeatable Comment':
                        set_cmt(current_address,str(value),1)        

    """ Imports """
    def GetImports(self):
        def imp_cb(ea,name,ord):        
            imports.append([ea,name,ord])
            return True

        address_infos=[]
        self.import_addresses={}
        for i in xrange(0,get_import_module_qty()):
            module_name=get_import_module_name(i)
            if not module_name:
                self.logger.debug('Failed to get name: %d',i)
                continue
            imports=[]
            enum_import_names(i,imp_cb)
            for [ea,name,ord] in imports:
                address_infos.append(self.MakeAddressInfo(ea-self.ImageBase,name))

        return address_infos
               
    def GetIndirectCalls(self,start,end):
        instructions=[]
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            current=seg.startEA
            while current<seg.endEA:
                if isCode(GetFlags(current)): # and (GetFunctionFlags(current) & FUNC_LIB)==0:
                    inslen=decode_insn(current)
                    op=GetMnem(current)                    
                    if op=='call' or op=='jmp':
                        operand=cmd.Operands[0]

                        interesting_call=False
                        if operand.type in (o_reg, o_mem, o_displ, o_phrase):
                            interesting_call=True

                        if interesting_call:
                            operand_str=GetOpnd(current,0)
                            if operand_str.find('cs:')>=0 or operand_str.find('ds:')>=0:
                                interesting_call=False

                        if interesting_call:
                            self.logger.debug('%x %s %s (%s)', current, op, operand_str, self.OperandTypes[operand.type])
                            instructions.append(self.GetInstruction(current))

                current+=get_item_size(current)

        return instructions

    def FindUnregonizedFunctions(self):
        unrecognized_functions=[]
        for seg_ea in Segments():
            for ea in Heads(seg_ea,SegEnd(seg_ea)):
                if isCode(GetFlags(ea)):
                    if len(self.GetCREFTo(ea))==0:
                        func=get_func(ea)
                        if func is None or func.startEA!=ea:
                            unrecognized_functions.append(ea)
                            
        return unrecognized_functions

    def PatchBytes(self,addr, str):
        for i, c in enumerate(str):
            idc.PatchByte(addr+i, ord(c))

    def FindUtilityFunctions(self,threshold=10):
        utility_functions={}
        for function_info in self.GetFunctions():
            ea=function_info['Address']
            cref_to=self.GetCREFTo(ea)

            if len(cref_to)>=threshold:
                utility_functions[ea]=True
                
        return utility_functions

    def GetFunctionTree(self,ea=None,threshold=10,filter=None):
        call_ref_maps={}
        function_list=[]
        function_instructions={}

        utility_functions=self.FindUtilityFunctions(threshold)        

        def GetCallRefs(call_ea,ea,level=0):
            func_name=self.GetName(ea)
            function_list.append((level,func_name,ea,call_ea))
            
            if utility_functions.has_key(ea):
                return

            if call_ref_maps.has_key(ea):
                return

            call_ref_maps[ea]=True
            (call_refs,indirect_reg_call_refs,instructions)=self.GetFunctionCallRefs(ea,filter)
            function_instructions[func_name]=instructions
            for (caller,operands) in indirect_reg_call_refs:
                if len(operands)>0:
                    operand_str=self.GetOperandStr(operands[0])
                else:
                    operand_str=''
                function_list.append((level+1,str(operand_str),0,caller))
                
            for (call_address,call_ref) in call_refs:
                GetCallRefs(call_address,call_ref,level+1)
                
        func_addr=self.GetFunctionAddress(ea)
        GetCallRefs(func_addr,func_addr)
        
        return (function_list,function_instructions)
        
    def GetFunctionTreeInstructions(self,ea=None,filter=None):
        (function_list,function_instructions)=self.GetFunctionTree(ea=ea,filter=filter)
        return function_instructions

    def Export(self, filename='', type='LIST'):        
        if filename=='':
            filename=idc.GetInputFile() + ".lst"

        tmp_filename='tmp.lst'
        idc.GenerateFile(idc.OFILE_LST, tmp_filename, 0, idc.BADADDR, 0)
        
        rfd=open(tmp_filename,'r')
        fd=open(filename,'a')
        fd.write(rfd.read())
        rfd.close()
        fd.close()

    def WaitAnalysis(self):
        autoWait()
        
    def GetStackCalls(self):
        instructions=[]
        for instruction in self.GetIndirectCalls():
            ea = instruction['Address']
            block_parser=Block(ea)
            print '* Analyzing %s call at %x (%s)' % (block_parser.GetFuncName(),ea,instruction['Disasm'])

            stack_access_addresses={}
            for blocks in block_parser.GetBlockPaths():
                parser_list=[]
                for block in blocks:
                    for (address,bytes) in block_parser.GetInstructionBytes(block):
                        parser=Disasm.Vex.Parser(bytes,address,'x64')
                        parser_list.append(parser)

                tracker=Disasm.Vex.Tracker(parser_list)
                
                for dump in tracker.Trace('rip'):
                    if dump['Data']['Type']=='Get' and dump['Data']['Value']=='rsp':
                        stack_access_addresses[dump['Address']]=1			
                        logger.debug('\tBlock list: '+block_parser.DumpBlocks(blocks))
                        logger.debug('\t\tFound stack reference at %x',dump['Address'])
                        break

            for stack_access_address in stack_access_addresses.keys():
                print '> %s' % block_parser.GetFuncName()
                print '  Stack variable at %x (%s)' % (stack_access_address,self.GetDisasmLine(stack_access_address))
                print '  Used for call at %x (%s)' % (ea,instruction['Disasm'])
                instructions.append({
                    'Instruction': instruction, 
                    'StackAccessAddress': stack_access_address
                })
                
        return instructions

    def GetBytes(self,len=1024):
        for i in range(0,get_segm_qty(),1):
            seg=getnseg(i)
            addr=seg.startEA
            while addr<seg.endEA:
                if seg.endEA-addr < len:
                    bytes=GetManyBytes(addr, seg.endEA-addr)
                    if bytes!=None:
                        yield (addr, bytes)
                else:
                    bytes=GetManyBytes(addr, len)
                    if bytes!=None:
                        yield (addr, bytes)
                addr+=len

    def Redefine(self,addr,len,type,data_type='DWORD'):
        MakeUnkn(addr,len)
        
        if type=='Code':
            MakeCode(addr)
        elif type=='Data':
            ff_type=FF_BYTE
            
            if data_type=='QWORD':
                ff_type=FF_QWRD
            elif data_type=='DWORD':
                ff_type=FF_DWRD
            elif data_type=='WORD':
                ff_type=FF_WORD
            elif data_type=='ASCII':
                ff_type=FF_ASCI

            MakeData(addr, ff_type, len, 0)

    def MakeFunction(self,addr,len):
        MakeFunction(addr,addr+len)

    def AddArgsOption(self, *args, **kwargs):
        self.Parser.add_option(*args, **kwargs)

    def ParseArgs(self):
        argv=[]
        for i in xrange(1,len(idc.ARGV)):
            argv.append(idc.ARGV[i])

        (self.Options,self.Args)=self.Parser.parse_args(argv)

    def Exit(self):
        if self.Options.exit:
            idc.Exit(0)

if __name__=='__main__':
    logger=logging.getLogger(__name__)
    disasm=Disasm()

    disasm.GetFunctionTreeInstructions(
        filter={'Op': ['call', 'jmp'], 'Target': 'Indirect'}
    )
