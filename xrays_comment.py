import idaapi
import idautils
import ida_kernwin

# https://hex-rays.com/products/ida/support/idapython_docs/idaapi-module.html
ITP = {
    1: "ITP_ARG1",
    64: "ITP_ARG64",
    66: "ITP_ASM",
    74: "ITP_BLOCK1",
    75: "ITP_BLOCK2",
    65: "ITP_BRACE1",
    72: "ITP_BRACE2",
    1073741824: "ITP_CASE",
    73: "ITP_COLON",
    70: "ITP_CURLY1",
    71: "ITP_CURLY2",
    68: "ITP_DO",
    67: "ITP_ELSE",
    0: "ITP_EMPTY",
    65: "ITP_INNER_LAST",
    69: "ITP_SEMI",
    536870912: "ITP_SIGN",
}

class XRayComments(ida_kernwin.Choose):
    cmts_list = []

    def __init__(self):
        super(XRayComments, self).__init__("XRayComments", [["Address", (8*2)+2], ["Preciser", 10],["Comment", 100]])
        self.populate()
    
    def populate(self):
        for ea in idautils.Functions():
            try:
                cfunc = idaapi.decompile(ea)
            except idaapi.DecompilationFailure as ex:
                print("Unable to get comments\n{}".format(ex))
                continue

            num_cmts = idaapi.user_cmts_size(cfunc.user_cmts)

            # std::map<treeloc_t, citem_cmt_t>
            t_c = idaapi.user_cmts_begin(cfunc.user_cmts)
            for i in range(num_cmts):
                t = idaapi.user_cmts_first(t_c)
                c = idaapi.user_cmts_second(t_c)
                self.cmts_list.append([hex(t.ea), str(t.itp), c.c_str()])
                
                t_c = idaapi.user_cmts_next(t_c)

    def OnClose(self):
        global XRAYCOMMENTS
        del XRAYCOMMENTS

    def OnGetLine(self, n):
        return self.cmts_list[n]
        
    def OnGetSize(self):
        return len(self.cmts_list)

    def OnSelectLine(self, n):
        idaapi.jumpto(int(self.cmts_list[n][0], base=16))

    def show(self):
        return False if self.Show() < 0 else True 

XRAYCOMMENTS = XRayComments()
XRAYCOMMENTS.show()
