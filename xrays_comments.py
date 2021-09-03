import idautils
import ida_idaapi
import ida_kernwin
import ida_hexrays

# https://hex-rays.com/products/ida/support/idapython_docs/idaapi-module.html
ITP = {
    1: 'ITP_ARG1',
    64: 'ITP_ARG64',
    66: 'ITP_ASM',
    74: 'ITP_BLOCK1',
    75: 'ITP_BLOCK2',
    65: 'ITP_BRACE1',
    72: 'ITP_BRACE2',
    1073741824: 'ITP_CASE',
    73: 'ITP_COLON',
    70: 'ITP_CURLY1',
    71: 'ITP_CURLY2',
    68: 'ITP_DO',
    67: 'ITP_ELSE',
    0: 'ITP_EMPTY',
    65: 'ITP_INNER_LAST',
    69: 'ITP_SEMI',
    536870912: 'ITP_SIGN',
}

PLUGIN_NAME = "XRayComments"
PLUGIN_VERSION = "0.1"

class XRayComments(ida_kernwin.Choose):
    cmts_list = []

    def __init__(self):
        super(XRayComments, self).__init__("XRayComments", [["Address", (8*2)+2], ["Preciser", 10], ["Comment", 100]])
        self.populate()
    
    def populate(self):
        self.cmts_list = []
        
        for f in idautils.Functions():
            try:
                cfunc = ida_hexrays.decompile(f)
            except ida_hexrays.DecompilationFailure as ex:
                ida_kernwin.msg('XRayComments: {}, unable to get comments\n'.format(ex))
                continue

            # std::map<treeloc_t, citem_cmt_t>
            t_c = ida_hexrays.user_cmts_begin(cfunc.user_cmts)
            num_cmts = ida_hexrays.user_cmts_size(cfunc.user_cmts)
            for _ in range(num_cmts):
                t = ida_hexrays.user_cmts_first(t_c)
                c = ida_hexrays.user_cmts_second(t_c)
                self.cmts_list.append([hex(t.ea), str(t.itp), c.c_str()])
                
                t_c = ida_hexrays.user_cmts_next(t_c)

    def OnGetLine(self, n):
        return self.cmts_list[n]
        
    def OnGetSize(self):
        return len(self.cmts_list)

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(int(self.cmts_list[n][0], base=16))

class XRayCommentsPlugin(ida_idaapi.plugin_t):
    comment = "Show all decompiler comments written by user"
    version = PLUGIN_VERSION
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Shift+C"
    flags = ida_idaapi.PLUGIN_FIX
    help = "Contact in twitter: @MrNox_"

    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("{}: Loaded!".format(PLUGIN_NAME))
            return ida_idaapi.PLUGIN_KEEP
        else:
            ida_kernwin.msg("{}: Decompiler not available, skipping.".format(PLUGIN_NAME))
            return ida_idaapi.PLUGIN_SKIP

    def run(self, _):
        plg = XRayComments()
        plg.Show("{} {}".format(PLUGIN_NAME, PLUGIN_VERSION))
        pass
        
    def term(self):
        ida_hexrays.term_hexrays_plugin()
        
def PLUGIN_ENTRY():
    return XRayCommentsPlugin()

