import Breakpoints

if __name__=='__main__':
    breakpoints=Breakpoints.Util()
    breakpoints.Add("FunctionTree","IndirectCall")
    breakpoints.Save()
    breakpoints.Exit()