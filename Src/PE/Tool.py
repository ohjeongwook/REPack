import sys
import pprint
import shutil
import pefile

class PEFile:
    def __init__(self,filename):
        self.Filename=filename
        self.PE=pefile.PE(filename)

        print 'ImageBase: %x' % (self.PE.OPTIONAL_HEADER.ImageBase)
        print 'AddressOfEntryPoint: %x' % (self.PE.OPTIONAL_HEADER.AddressOfEntryPoint)
        print 'NumberOfRvaAndSizes: %x' % (self.PE.OPTIONAL_HEADER.NumberOfRvaAndSizes)
        print 'NumberOfSections: %x' % (self.PE.FILE_HEADER.NumberOfSections)

    def FindRawOffsetByVA(self,addr):
        for section in self.PE.sections:
            if section.VirtualAddress<=addr and addr<=section.VirtualAddress+section.SizeOfRawData:
                print '\tName: [%s]' % section.Name
                print '\tVirtualAddress: %x' % section.VirtualAddress
                print '\tMisc_VirtualSize: %x' % section.Misc_VirtualSize
                print '\tPointerToRawData: %x' % section.PointerToRawData
                print '\tSizeOfRawData: %x' % section.SizeOfRawData
                return section.PointerToRawData+(addr-section.VirtualAddress)
        return 0

    def OverwriteEntry(self,bytes,output_filename):
        entry_offset=self.FindRawOffsetByVA(self.PE.OPTIONAL_HEADER.AddressOfEntryPoint)
        shutil.copy(self.Filename,output_filename)
        fd=open(output_filename,'rb+')
        fd.seek(entry_offset)
        fd.write(bytes)
        fd.close()

    def DumpSections(self):
        max_offset=0
        sections={}
        for section in self.PE.sections:
            print '\tName: [%s]' % section.Name
            print '\tVirtualAddress: %x' % section.VirtualAddress
            print '\tMisc_VirtualSize: %x' % section.Misc_VirtualSize
            print '\tPointerToRawData: %x' % section.PointerToRawData
            print '\tSizeOfRawData: %x' % section.SizeOfRawData
            print ''
            
            if max_offset<section.PointerToRawData+section.SizeOfRawData:
                max_offset=section.PointerToRawData+section.SizeOfRawData
                
        print 'Max offset: %x' % max_offset
        
    def FixSections(self, output_filename):
        print 'ImageBase: %x' % (pe.OPTIONAL_HEADER.ImageBase)
        print 'AddressOfEntryPoint: %x' % (pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        print 'NumberOfRvaAndSizes: %x' % (pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
        print 'NumberOfSections: %x' % (pe.FILE_HEADER.NumberOfSections)

        sections={}
        for section in pe.sections:
            print '\tName: [%s]' % section.Name
            print '\tVirtualAddress: %x' % section.VirtualAddress
            print '\tMisc_VirtualSize: %x' % section.Misc_VirtualSize
            print '\tPointerToRawData: %x' % section.PointerToRawData
            print '\tSizeOfRawData: %x' % section.SizeOfRawData
            print ''
            
            section.PointerToRawData=section.VirtualAddress
            sections[section.Name]=(section.PointerToRawData,section.SizeOfRawData)	

        if options.image_base:
            pe.OPTIONAL_HEADER.ImageBase=int(options.image_base,16)

        pe.write(output_filename)


if __name__=='__main__':
    import sys
    import os
    from optparse import OptionParser, Option

    parser=OptionParser(usage="usage: %prog [options] args")
    parser.add_option("-b","--image_base",dest="image_base",type="string",default="",metavar="IMAGE_BASE",help="Image base")
    parser.add_option("-c","--command",dest="command",type="string",default="",metavar="FIX_SECTIONS",help="Commands (fix, patch)")
    
    (options,args)=parser.parse_args(sys.argv)

    filename=args[1]
    pe_file = PEFile(filename)

    if options.command=='fix':
        output_filename=args[2]
        pe_file.FixSections(output_filename)
    elif options.command=='patchentry':        
        output_filename=args[2]
        newcode_filename=args[3]
        
        fd=open(patch,'rb')
        bytes=fd.read()
        fd.close()
        pe_file.OverwriteEntry(bytes,output_filename)
