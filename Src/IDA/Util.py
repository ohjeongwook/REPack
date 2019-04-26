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
import OperandTypes

class Util:
    def GetSelectionStart(self):
        (ea,end) = self.GetSelection()
        return ea

    def GetFunctionAddress(self,ea=None):
        if ea==None:
            ea=self.GetSelectionStart()

        func=get_func(ea)

        if func:
            return func.startEA
        else:
            return -1

    """Names"""
    def GetName(self, current_address):
        return get_true_name(current_address)

    def GetFuncName(self,ea,demangle=True):
        name=get_func_name(ea)
        demangled_name=idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        
        if demangled_name==None:
            return name
        else:
            return demangled_name

    def IsReservedName(self,name):
        if name.startswith("sub_") or \
            name.startswith("loc_") or \
            name.startswith("locret_") or \
            name.startswith("dword_") or \
            name.startswith("word_") or \
            name.startswith("unknown_") or \
            name.startswith("unk_") or \
            name.startswith("dbl_") or \
            name.startswith("stru_") or \
            name.startswith("byte_") or \
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

    """REFs"""
    def GetItemSize(self,ea):
        return get_item_size(ea)

    def GetNextItem(self,ea):
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
