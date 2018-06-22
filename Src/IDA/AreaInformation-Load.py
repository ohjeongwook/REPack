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

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

if __name__=='__main__':
    disasm=IDA.Analysis.Disasm()
    
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

        filename=form.AskSaveFileName("JSON (*.json)")

    if not filename:
        filename='AreaInformation.db'

    if filename:
        disasm.LoadAreaInformation(filename)
    disasm.Exit()
