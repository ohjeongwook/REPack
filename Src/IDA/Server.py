import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'D:\Analysis\REPack\Src')
import functools
import Queue
import pprint
import json
import logging
import traceback
import zerorpc

from idaapi import *
from idc import *
import idaapi
import idautils
from idaapi import PluginForm

import Disasm
import Disasm.Vex
import Disasm.Tool
from Util.Config import *
from WinDBG.RunLog import *
from TraceLoader import *
import REPack

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

class IDASyncError(Exception): pass

class IDASafety:
    SAFE_NONE = 0
    SAFE_READ = 1
    SAFE_WRITE = 2

call_stack = Queue.LifoQueue()

def sync_wrapper(ff,safety_mode):
    logger.debug('sync_wrapper: {}, {}'.format(ff.__name__,safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ,IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode,ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    queue = Queue.Queue()
    def runned():
        logger.debug('Inside runned')

        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                            'function {} from {}').format(ff.__name__,last_func_name)
            logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            queue.put(ff())
        except:
            queue.put(None)
            traceback.print_exc(file=sys.stdout)
        finally:
            call_stack.get()
            logger.debug('Finished runned')

    idaapi.execute_sync(runned,safety_mode)
    return queue.get()

def idawrite(f):
    @functools.wraps(f)
    def wrapper(*args,**kwargs):
        ff = functools.partial(f,*args,**kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff,idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    @functools.wraps(f)
    def wrapper(*args,**kwargs):
        ff = functools.partial(f,*args,**kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff,idaapi.MFF_READ)
    return wrapper

class IDARPCServer(object):
    def __init__(self):
        self.IDADisasm=Analysis.Disasm()
        self.DisasmTool=Disasm.Tool.Analyzer('x86',64)

    @idaread
    def GetFunctionInstructions(self,ea=None):
        return self.IDADisasm.GetFunctionInstructions(ea)
        
    @idaread
    def GetFunctions(self):
        return self.IDADisasm.GetFunctions()
        
    @idaread
    def GetFunctionHashes(self):
        return self.IDADisasm.GetFunctionHashes(hash_types=['op'])
        
    @idaread
    def GetFunctionTree(self,ea=None,threshold=10):
        return self.IDADisasm.GetFunctionTree(ea,threshold)

    @idaread
    def GetImports(self):
		return self.IDADisasm.GetImports()

    @idawrite
    def LoadFunctionNameByHashes(self,filename):
        return self.IDADisasm.LoadFunctionNameByHashes(filename)

    @idawrite
    def LoadNamesAndComments(self,filename):
        return self.IDADisasm.LoadNamesAndComments(filename)
        
    @idawrite    
    def SetCmts(self, cmt_map):
        for kv in cmt_map.items():
            self.IDADisasm.SetCmt(kv[0], kv[1])

    @idaread
    def GetIndirectCalls(self):
        return self.IDADisasm.GetIndirectCalls()

    @idaread
    def DisasmBytes(self,bytes,addr):
        return self.DisasmTool.Disasm(bytes,addr)

    @idawrite
    def LoadWindbgLog(self, filename):
        record_analyzer=RunLogAnalyzer(filename)
        def address_callback(address):
            print '%x' % address
            idaapi.set_item_color(address, 0x00ff00)

        record_analyzer.RunAddressCallback(address_callback)

    @idaread
    def Export(self, lst_filename=''):
        return self.DisasmTool.Export(lst_filename)

import threading

class ThreadWorker(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        s = zerorpc.Server(IDARPCServer())
        s.bind("tcp://0.0.0.0:4242")
        s.run()

thread_worker = ThreadWorker()
thread_worker.start()
