import Disasm

disasm=Analysis.Disasm()
(function_list,function_instructions)=disasm.GetFunctionTree(threshold=10000)
for (level, name, address, caller_address) in function_list:
    cmt=disasm.GetCmt(caller_address)
    print '%s%s (%.8x) @ %.8x ; %s' % ('    '*level, name, address, caller_address, cmt)
