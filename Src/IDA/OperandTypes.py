from idaapi import *
from idautils import *
from idc import *
import idc

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

Values={}
Values[o_void]="Void"
Values[o_far]="Far"
Values[o_near]="Near"
Values[o_reg]="Register"
Values[o_imm]="Immediate"                    
Values[o_mem]="Memory"
Values[o_displ]="Displacement"
Values[o_phrase]="Phrase"

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
