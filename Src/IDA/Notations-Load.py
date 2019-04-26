import sys
import os
if os.environ.has_key('REPack'):
    sys.path.append(os.environ['REPack'])
else:
    sys.path.append(r'..\\')
import pprint
import logging
import json

from Disasm import Disasm

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

if __name__=='__main__':
    disasm=Disasm()
    
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
        print 'Loading file:', filename
        disasm.LoadNotations(filename, hash_types=[])
    disasm.Exit()
