import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'..\\')
import pprint
import logging
import json

import Analysis

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

if __name__=='__main__':
    disasm=Analysis.Disasm()
    
    if len(disasm.Args)==0:
        import UI

        global form

        title='Breakpoints-UI'
        try:
            form
            form.OnClose(form)
            form=UI.Form(title)
        except:
            form=UI.Form(title)

        form.Show()

        filename=form.AskOpenFileName("DB (*.db)")

    if not filename:
        filename='InstructioNotations.db'

    if filename:
        print 'Loading file:', save_filename
        disasm.LoadInstructionNotations(filename)
    disasm.Exit()
