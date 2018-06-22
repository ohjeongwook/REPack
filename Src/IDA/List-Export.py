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
    
    save_filename=''
    if len(disasm.Args)>0:
        save_filename=disasm.Args[0]
    else:        
        import UI

        global form

        title='List-Export-UI'
        try:
            form
            form.OnClose(form)
            form=UI.Form(title)
        except:
            form=UI.Form(title)

        form.Show()

        save_filename=form.AskSaveFileName("LIST (*.lst)")

    if not save_filename:
        save_filename=disasm.GetFilename()+r'.lst'

    if save_filename:
        print 'Save', save_filename
        disasm.Export(save_filename)
    disasm.Exit()
