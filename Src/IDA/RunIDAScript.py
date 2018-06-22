import os
import sys
import dircache
import re
import subprocess

class Runner:
    IDAQ=r"C:\Program Files (x86)\IDA 6.95\idaq.exe"
    def __init__(self,args,regex=''):
        self.ArgStr=''                
        for arg in args:
            if self.ArgStr:
                self.ArgStr+=' '
            self.ArgStr+='""%s""' % arg

        self.RegEx = re.compile(regex,re.IGNORECASE)

    def SetIDAPath(self,filename):
        self.IDAQ=filename

    def RunScriptOnDir(self,dirname='.'):
        for filename in dircache.listdir(dirname):
            full_path=os.path.join(dirname, filename)
            if os.path.isdir(full_path):
                self.RunScriptOnDir(full_path)
            else:
                if self.RegEx.search(filename):
                    cmds=[]
                    cmds.append(self.IDAQ)
                    cmds.append(r'-S%s' % (self.ArgStr))
                    cmds.append(full_path)
                    print '> Running', cmds
                    p=subprocess.Popen(cmds)
                    p.wait()

if __name__=='__main__':
    import sys
    from optparse import OptionParser, Option

    parser=OptionParser(usage="usage: %prog [options] args")	
    parser.add_option("-R","--root_folder",dest="root_folder",type="string",default=".",metavar="LOG_FILENAME",help="Log filename")
    parser.add_option("-r","--regex",dest="regex",type="string",default="\.idb$",metavar="REGEX",help="Log filename")
	
    (options,args)=parser.parse_args(sys.argv)
    
    runner=Runner(args[1:],regex=options.regex)
    runner.RunScriptOnDir(options.root_folder)
