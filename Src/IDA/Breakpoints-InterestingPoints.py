import Breakpoints

if __name__=='__main__':
    breakpoints=Breakpoints.Util()
    breakpoints.AddFunctions()
    breakpoints.Add("All","DisplacementCall")
    breakpoints.Add("All","Pointer")
    breakpoints.Add("All","IndirectCall")
    breakpoints.Save()
    breakpoints.Exit()
