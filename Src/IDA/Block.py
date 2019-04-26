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
import OperandTypes

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
            return self.IDAUtil.GetFuncName(root,demangle=demangle)