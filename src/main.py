"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only
"""

from typing import List, Tuple, Optional, cast

import os
import shlex  # clang_arg string -> argv

from html.parser import HTMLParser  # parse doxygen html
from argparse import ArgumentParser

from clang.cindex import Config

from header import Header
from module import rizin
from module_class import ModuleClass
from module_generic import ModuleGeneric
from module_director import ModuleDirector
from module_typemap import ModuleTypemap
from module_enum import ModuleEnum

### Parser ###
parser = ArgumentParser()
parser.add_argument("--output", "-o", required=True)
parser.add_argument("--clang-path", required=True)
parser.add_argument("--clang-args", required=True)
parser.add_argument("--rizin-inc-path", required=True)
parser.add_argument("--doxygen-html-path")
args = parser.parse_args()

Config.set_library_path(cast(str, args.clang_path))
clang_args = shlex.split(cast(str, args.clang_args))

### Include directories ###
rizin_inc_path = os.path.abspath(cast(str, args.rizin_inc_path))
for segments in [
    ["."],
    ["sdb"],
    # meson project
    ["..", "..", "build"],
    ["..", "..", "subprojects", "sdb", "src"],
    ["..", "..", "build", "subprojects", "sdb"],
]:
    path = os.path.abspath(os.path.join(rizin_inc_path, *segments))
    if os.path.exists(path):
        clang_args.append(f"-I{path}")

clang_args.append("-DRZ_BINDINGS")
Header.clang_args = clang_args
Header.rizin_inc_path = rizin_inc_path

# [[Docs]]
doxygen_html_path = cast(Optional[str], args.doxygen_html_path)
if doxygen_html_path is not None:
    rizin.enable_sphinx = True
    rizin.doxygen_html_path = doxygen_html_path

    class FuncParser(HTMLParser):
        """
        Parse doxygen globals_func.html list elements
        """

        func: Optional[str]
        in_a: bool
        a_href: Optional[str]

        mappings: List[Tuple[str, str]]

        def __init__(self) -> None:
            super().__init__()
            self.reset()

        def reset(self) -> None:
            super().reset()
            self.func = None
            self.in_a = False
            self.a_href = None
            self.mappings = []

        def handle_starttag(
            self, tag: str, attrs: List[Tuple[str, Optional[str]]]
        ) -> None:
            if tag == "a":
                self.in_a = True
                self.a_href = next(value for key, value in attrs if key == "href")

        def handle_data(self, data: str) -> None:
            if self.in_a:
                assert self.a_href
                self.mappings.append((self.a_href, data))
            elif not self.func:
                self.func = data

        def handle_endtag(self, tag: str) -> None:
            if tag == "a":
                self.in_a = False

    funcparser = FuncParser()

    # Parse Doxygen functions
    for filename in [
        f"globals_func_{chr(i)}.html" for i in range(ord("a"), ord("z") + 1)
    ] + ["globals_func.html"]:
        with open(
            os.path.join(doxygen_html_path, filename), encoding="utf-8"
        ) as globals_file:
            for line in globals_file.readlines():
                if line.startswith("<li>"):
                    funcparser.reset()
                    funcparser.feed(line)
                    assert funcparser.func
                    func_name = funcparser.func[: funcparser.func.find("(")]
                    rizin.doxygen_funcs[func_name] = funcparser.mappings

### RzList
list_h = Header("rz_list.h")
rz_list_iter = ModuleGeneric(list_h, "RzListIter")
rz_list_iter.add_method(
    list_h, "rz_list_iter_get_next", rename="next", generic_ret=True
)
rz_list_iter.add_method(
    list_h, "rz_list_iter_get_data", rename="data", generic_ret=True
)

rz_list = ModuleGeneric(list_h, "RzList", dependencies=["RzListIter"], pointer=True)
rz_list.add_method(list_h, "rz_list_length", rename="length")
rz_list.add_method(list_h, "rz_list_length", rename="__len__")

rz_list.add_method(list_h, "rz_list_first", rename="first", generic_ret=True)
rz_list.add_method(list_h, "rz_list_last", rename="last", generic_ret=True)

rz_list.add_method(
    list_h, "rz_list_prepend", rename="prepend", generic_ret=True, generic_args={"data"}
)
rz_list.add_method(
    list_h, "rz_list_append", rename="append", generic_ret=True, generic_args={"data"}
)
rz_list.add_method(list_h, "rz_list_iterator", rename="iterator", generic_ret=True)

rz_list.add_extension(
    "%pythoncode %{",
    "    def __iter__(self):",
    "        return RzListIterator(self)",
    "%}",
)

### RzVector, RzPVector ###
vector_h = Header("rz_vector.h")
rz_vector = ModuleGeneric(vector_h, "RzVector")
rz_vector.add_method(vector_h, "rz_vector_len", rename="length")
rz_vector.add_method(vector_h, "rz_vector_len", rename="__len__")
rz_vector.add_method(vector_h, "rz_vector_head", rename="head", generic_ret=True)
rz_vector.add_method(vector_h, "rz_vector_tail", rename="tail", generic_ret=True)
rz_vector.add_method(vector_h, "rz_vector_index_ptr", rename="at", generic_ret=True)
rz_vector.add_method(
    vector_h, "rz_vector_push", rename="push", generic_ret=True, generic_args={"x"}
)

rz_vector.add_extension(
    "%pythoncode %{",
    "    def __iter__(self):",
    "        return RzVectorIterator(self)",
    "%}",
)

rz_pvector = ModuleGeneric(vector_h, "RzPVector", pointer=True)
rz_pvector.add_method(vector_h, "rz_pvector_len", rename="length")
rz_pvector.add_method(vector_h, "rz_pvector_len", rename="__len__")
rz_pvector.add_method(vector_h, "rz_pvector_head", rename="head", generic_ret=True)
rz_pvector.add_method(vector_h, "rz_pvector_tail", rename="tail", generic_ret=True)
rz_pvector.add_method(vector_h, "rz_pvector_at", rename="at", generic_ret=True)
rz_pvector.add_method(
    vector_h, "rz_pvector_push", rename="push", generic_ret=True, generic_args={"x"}
)

rz_pvector.add_extension(
    "%pythoncode %{",
    "    def __iter__(self):",
    "        return RzPVectorIterator(self)",
    "%}",
)

### rz_types ###
types_h = Header("rz_types.h")
ModuleEnum(types_h, prefix="RZ_PERM_")

### rz_core_t ###
core_h = Header("rz_core.h")
Header("rz_cmp.h")  # for RzCoreCmpWatcher
rz_core = ModuleClass(
    core_h,
    struct="rz_core_t",
    rename="RzCore",
    rename_fields={"autocomplete": "_autocomplete", "visual": "_visual"},
)
rz_core.add_constructor(core_h, "rz_core_new")
rz_core.add_destructor(core_h, "rz_core_free")

# Ignore format strings
core_h.ignore(
    "rz_core_notify_begin",
    "rz_core_notify_done",
    "rz_core_notify_error",
    "rz_core_cmd_strf",
    "rz_core_cmdf",
    "rz_core_syscallf",
)

rz_core.add_method(
    core_h,
    "rz_core_file_open_load",
    rename="file_open_load",
    default_args={"addr": "0", "perms": "0", "write_mode": "0"},
)
rz_core.add_method(
    core_h,
    "rz_core_file_open",
    rename="file_open",
    default_args={"flags": "0", "loadaddr": "UT64_MAX"},
)
rz_core.add_prefixed_methods(core_h, "rz_core_")
rz_core.add_prefixed_funcs(core_h, "rz_core_")

rz_core_file = ModuleClass(core_h, typedef="RzCoreFile")

### rz_bin ###
bin_h = Header("rz_bin.h")
rz_bin_file = ModuleClass(bin_h, typedef="RzBinFile")
rz_bin_file.add_prefixed_methods(bin_h, "rz_bin_file_")
rz_bin = ModuleClass(
    bin_h, typedef="RzBin", rename_fields={"cur": "_cur", "strpurge": "_strpurge"}
)
rz_bin.add_prefixed_methods(bin_h, "rz_bin_")
rz_bin.add_prefixed_funcs(bin_h, "rz_bin_")
rz_bin_options = ModuleClass(bin_h, typedef="RzBinOptions")
rz_bin_info = ModuleClass(bin_h, typedef="RzBinInfo")

rz_bin_sym = ModuleClass(bin_h, typedef="RzBinSymbol")
rz_list.add_specialization_extension(
    "RzBinSymbol",
    "RzList_RzBinSymbol() {",
    "    return rz_list_newf((RzListFree)rz_bin_symbol_free);",
    "}",
)

rz_bin_section = ModuleClass(bin_h, typedef="RzBinSection")
rz_list.add_specialization_extension(
    "RzBinSection",
    "RzList_RzBinSection() {",
    "    return rz_list_newf((RzListFree)rz_bin_section_free);",
    "}",
)

ModuleDirector(bin_h, "RzBinPlugin")
ModuleClass(bin_h, typedef="RzBinPlugin")

ModuleEnum(bin_h, prefix="RZ_BIN_TYPE_")
ModuleEnum(bin_h, prefix="RZ_BIN_BIND_")

ModuleClass(bin_h, typedef="RzBinMap")
rz_list.add_specialization_extension(
    "RzBinMap",
    "RzList_RzBinMap() {",
    "    return rz_list_newf((RzListFree)rz_bin_map_free);",
    "}",
)

### rz_analysis ###
analysis_h = Header("rz_analysis.h")
rz_analysis = ModuleClass(
    analysis_h,
    typedef="RzAnalysis",
    ignore_fields={"leaddrs"},
    rename_fields={"type_links": "_type_links"},
)
rz_analysis_function = ModuleClass(analysis_h, typedef="RzAnalysisFunction")
rz_analysis_function.add_method(
    analysis_h, "rz_analysis_function_delete", rename="delete_self"
)
rz_analysis_function.add_prefixed_methods(analysis_h, "rz_analysis_function_")

rz_analysis.add_method(analysis_h, "rz_analysis_reflines_get", rename="get_reflines")
rz_analysis.add_prefixed_methods(analysis_h, "rz_analysis_")
rz_analysis.add_prefixed_funcs(analysis_h, "rz_analysis_")

### rz_cons ###
cons_h = Header("rz_cons.h")
rz_cons = ModuleClass(
    cons_h,
    typedef="RzCons",
    rename_fields={
        "lastline": "_lastline",
        "echo": "_echo",
        "highlight": "_highlight",
        "newline": "_newline",
        "filter": "_filter",
        "flush": "_flush",
        "input": "_input",
        "enable_highlight": "_enable_highlight",
    },
)
cons_h.ignore(
    "rz_cons_printf",
    "rz_cons_printf_list",
    "rz_cons_yesno",
)
rz_cons.add_prefixed_methods(cons_h, "rz_cons_")
rz_cons.add_prefixed_funcs(cons_h, "rz_cons_")

### rz_buf ###
buf_h = Header("rz_util/rz_buf.h")
ModuleEnum(buf_h, "RZ_BUF_SET", "RZ_BUF_CUR", "RZ_BUF_END")
rz_buf = ModuleClass(buf_h, typedef="RzBuffer")

for name in [
    "append_bytes",
    "prepend_bytes",
    "set_bytes",
    "insert_bytes",
    "write",
    "write_at",
    "read",
    "read_at",
]:
    rz_buf.add_method(
        buf_h,
        f"rz_buf_{name}",
        rename=name,
        typemaps=[
            ModuleTypemap(
                "buffer_len",
                "unsigned char * buf, unsigned long long len",
            )
        ],
    )

rz_buf.add_method(buf_h, "rz_buf_seek", rename="seek")

### rz_cmd ###
cmd_h = Header("rz_cmd.h")
rz_cmd = ModuleClass(cmd_h, typedef="RzCmd")
rz_cmd_desc_help = ModuleClass(cmd_h, typedef="RzCmdDescHelp")
rz_cmd_desc_arg = ModuleClass(cmd_h, typedef="RzCmdDescArg")
rz_cmd_arg_type = ModuleEnum(cmd_h, typedef="RzCmdArgType")

### rz_num ###
num_h = Header("rz_util/rz_num.h")
rz_num = ModuleClass(num_h, typedef="RzNum")
rz_num.add_prefixed_methods(num_h, "rz_num_")
rz_num.add_prefixed_funcs(num_h, "rz_num_")

### rz_flag ###
flag_h = Header("rz_flag.h")
rz_flag_item = ModuleClass(flag_h, typedef="RzFlagItem")
rz_flag_item.add_prefixed_methods(flag_h, "rz_flag_item_")

rz_flag = ModuleClass(flag_h, typedef="RzFlag", ignore_fields={"tags"})
rz_flag.add_prefixed_methods(flag_h, "rz_flag_")
rz_flag.add_prefixed_funcs(flag_h, "rz_flag_")

### rz_main ###
main_h = Header("rz_main.h")
rz_main = ModuleClass(main_h, typedef="RzMain")
rz_main.add_constructor(main_h, "rz_main_new")
rz_main.add_destructor(main_h, "rz_main_free")
rz_main.add_prefixed_methods(main_h, "rz_main_")
rz_main.add_prefixed_funcs(main_h, "rz_main_")

output_path = cast(str, args.output)
with open(os.path.join(output_path, "rizin.i"), "w", encoding="utf-8") as output:
    rizin.write_io(output)

if rizin.enable_sphinx:
    sphinx_path = os.path.join(output_path, "sphinx")
    try:
        os.mkdir(sphinx_path)
    except FileExistsError:
        pass

    rizin.write_sphinx(sphinx_path)
