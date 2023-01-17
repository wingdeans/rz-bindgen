"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only
"""

from typing import OrderedDict, Callable

import concurrent.futures

from cparser_header import HeaderBuilder, Header
from binding_class import Class
from binding_director import Director
from binding_enum import Enum, MacroEnum
from binding_generic import Generic
from binding_typemap import buffer_len_typemap, const_buffer_len_typemap

HeaderFunc = Callable[[Header], None]
threaded_headers: OrderedDict[str, HeaderFunc] = OrderedDict()


def threaded_header(name: str) -> Callable[[HeaderFunc], None]:
    """
    Registers a header to be parsed by clang in parallel

    Decorates a function which takes a Header as an argument.

    Only the header parsing is done in parallel; the wrapped
    functions are called in the order they were registered
    """

    def decorator(func: HeaderFunc) -> None:
        assert name not in threaded_headers
        threaded_headers[name] = func

    return decorator


def run() -> None:
    """
    Parse headers in parallel, then run registered functions sequentially
    """

    with concurrent.futures.ThreadPoolExecutor() as executor:
        builders = [HeaderBuilder(name) for name in threaded_headers]
        translation_units = executor.map(HeaderBuilder.translation_unit, builders)
        for translation_unit, builder, func in zip(
            translation_units, builders, threaded_headers.values()
        ):
            for diagnostic in translation_unit.diagnostics:
                print(diagnostic)

            func(Header(translation_unit, builder))


############
# GENERICS #
############


@threaded_header("rz_list.h")
def bind_list(list_h: Header) -> None:
    """
    RzListIter, RzList
    """
    ### RzListIter ###
    rz_list_iter = Generic(list_h, "RzListIter", pointer=True)
    rz_list_iter.add_method("rz_list_iter_get_next", rename="next", generic_ret=True)
    rz_list_iter.add_method("rz_list_iter_get_data", rename="data", generic_ret=True)

    ### RzList ###
    rz_list = Generic(list_h, "RzList", dependencies=[rz_list_iter], pointer=True)
    rz_list.add_method("rz_list_length", rename="length")

    rz_list.add_method("rz_list_first", rename="first", generic_ret=True)
    rz_list.add_method("rz_list_last", rename="last", generic_ret=True)
    rz_list.add_method("rz_list_iterator", rename="iterator", generic_ret=True)

    rz_list.add_method(
        "rz_list_prepend", rename="prepend", generic_ret=True, generic_args={"data"}
    )
    rz_list.add_method(
        "rz_list_append", rename="append", generic_ret=True, generic_args={"data"}
    )

    rz_list.add_python_method("__len__(self)", "return self.length()")
    rz_list.add_python_method("__iter__(self)", "return RzListIterator(self)")

    # Specialized constructors
    rz_list.add_specialization_extension(
        "RzBinSymbol",
        "RzList_RzBinSymbol() {",
        "    return rz_list_newf((RzListFree)rz_bin_symbol_free);",
        "}",
    )
    rz_list.add_specialization_extension(
        "RzBinSection",
        "RzList_RzBinSection() {",
        "    return rz_list_newf((RzListFree)rz_bin_section_free);",
        "}",
    )
    rz_list.add_specialization_extension(
        "RzBinMap",
        "RzList_RzBinMap() {",
        "    return rz_list_newf((RzListFree)rz_bin_map_free);",
        "}",
    )


@threaded_header("rz_vector.h")
def bind_vector(vector_h: Header) -> None:
    """
    RzVector, RzPVector
    """
    ### RzVector ###
    rz_vector = Generic(vector_h, "RzVector")
    rz_vector.add_method("rz_vector_len", rename="length")
    rz_vector.add_method("rz_vector_head", rename="head", generic_ret=True)
    rz_vector.add_method("rz_vector_tail", rename="tail", generic_ret=True)
    rz_vector.add_method("rz_vector_index_ptr", rename="at", generic_ret=True)
    rz_vector.add_method(
        "rz_vector_push", rename="push", generic_ret=True, generic_args={"x"}
    )

    rz_vector.add_python_method("__len__(self)", "return self.length()")
    rz_vector.add_python_method("__iter__(self)", "return RzVectorIterator(self)")

    ### RzPVector ###
    rz_pvector = Generic(vector_h, "RzPVector", pointer=True)
    rz_pvector.add_method("rz_pvector_len", rename="length")
    rz_pvector.add_method("rz_pvector_head", rename="head", generic_ret=True)
    rz_pvector.add_method("rz_pvector_tail", rename="tail", generic_ret=True)
    rz_pvector.add_method("rz_pvector_at", rename="at", generic_ret=True)
    rz_pvector.add_method(
        "rz_pvector_push", rename="push", generic_ret=True, generic_args={"x"}
    )

    rz_pvector.add_python_method("__len__(self)", "return self.length()")
    rz_pvector.add_python_method("__iter__(self)", "return RzPVectorIterator(self)")


###########
# HEADERS #
###########


@threaded_header("rz_analysis.h")
def bind_analysis(analysis_h: Header) -> None:
    """
    RzAnalysis
    """
    analysis_h.ignore("rz_analysis_version")

    rz_analysis = Class(
        analysis_h,
        typedef="RzAnalysis",
        ignore_fields={"leaddrs"},
        rename_fields={"type_links": "_type_links"},
    )

    rz_analysis_function = Class(analysis_h, typedef="RzAnalysisFunction")
    rz_analysis_function.add_method("rz_analysis_function_delete", rename="delete_self")
    rz_analysis_function.add_prefixed_methods("rz_analysis_function_")

    rz_analysis.add_method("rz_analysis_reflines_get", rename="get_reflines")
    rz_analysis.add_prefixed_methods("rz_analysis_")
    rz_analysis.add_prefixed_funcs("rz_analysis_")

    Class(analysis_h, typedef="RzAnalysisBlock")
    Class(analysis_h, typedef="RzAnalysisEsil")
    Class(analysis_h, typedef="RzAnalysisPlugin")


@threaded_header("rz_asm.h")
def bind_asm(asm_h: Header) -> None:
    """
    RzAsm
    """
    Class(asm_h, typedef="RzAsm")  # TODO: Add functions
    Class(asm_h, typedef="RzAsmPlugin")


@threaded_header("rz_bin.h")
def bind_bin(bin_h: Header) -> None:
    """
    RzBin
    """
    bin_h.ignore("rz_bin_version")

    rz_bin_file = Class(bin_h, typedef="RzBinFile")
    rz_bin_file.add_prefixed_methods("rz_bin_file_")

    rz_bin = Class(
        bin_h, typedef="RzBin", rename_fields={"cur": "_cur", "strpurge": "_strpurge"}
    )
    rz_bin.add_prefixed_methods("rz_bin_")
    rz_bin.add_prefixed_funcs("rz_bin_")

    Class(bin_h, typedef="RzBinXtrPlugin")
    Class(bin_h, typedef="RzBinOptions")
    Class(bin_h, typedef="RzBinInfo")
    Class(bin_h, typedef="RzBinSymbol")
    Class(bin_h, typedef="RzBinSection")
    Class(bin_h, typedef="RzBinMap")

    Director(bin_h, "RzBinPlugin")

    MacroEnum(bin_h, prefix="RZ_BIN_TYPE_")
    MacroEnum(bin_h, prefix="RZ_BIN_BIND_")


@threaded_header("rz_util/rz_buf.h")
def bind_buf(buf_h: Header) -> None:
    """
    RzBuf
    """
    rz_buf = Class(buf_h, typedef="RzBuffer")

    # const ut8 *buffer, ut64 len
    for name in [
        "append_bytes",
        "prepend_bytes",
        "set_bytes",
        "insert_bytes",
        "write",
        "write_at",
    ]:
        rz_buf.add_method(
            f"rz_buf_{name}",
            rename=name,
            typemaps=[const_buffer_len_typemap],
        )

    # ut8 *buffer, ut64 len
    rz_buf.add_method("rz_buf_read", rename="read", typemaps=[buffer_len_typemap])
    rz_buf.add_method("rz_buf_read_at", rename="read_at", typemaps=[buffer_len_typemap])

    rz_buf.add_method("rz_buf_seek", rename="seek")

    MacroEnum(buf_h, "RZ_BUF_SET", "RZ_BUF_CUR", "RZ_BUF_END")


@threaded_header("rz_cmd.h")
def bind_cmd(cmd_h: Header) -> None:
    """
    RzCmd
    """
    Class(cmd_h, typedef="RzCmd")
    Class(cmd_h, typedef="RzCmdDesc", ignore_fields={"d"})
    Class(cmd_h, typedef="RzCmdDescHelp")
    Class(cmd_h, typedef="RzCmdDescArg")
    Enum(cmd_h, typedef="RzCmdArgType")


@threaded_header("rz_config.h")
def bind_config(config_h: Header) -> None:
    """
    RzConfig
    """
    config_h.ignore("rz_config_version")  # TODO: Fix in rizin
    rz_config = Class(config_h, typedef="RzConfig", rename_fields={"lock": "_lock"})
    rz_config.add_prefixed_methods("rz_config_")
    rz_config.add_prefixed_funcs("rz_config_")


@threaded_header("rz_cons.h")
def bind_cons(cons_h: Header) -> None:
    """
    RzCons
    """
    cons_h.ignore("rz_cons_version")

    rz_cons = Class(
        cons_h,
        typedef="RzCons",
        ignore_fields={"term_raw", "term_buf"},  # struct termios
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
    rz_cons.add_prefixed_methods("rz_cons_")
    rz_cons.add_prefixed_funcs("rz_cons_")

    Class(cons_h, typedef="RzLine")


@threaded_header("rz_cmp.h")
def bind_cmp(_: Header) -> None:
    """
    Needed for RzList_RzCoreCmpWatcher
    """


@threaded_header("rz_core.h")
def bind_core(core_h: Header) -> None:
    """
    RzCore
    """
    core_h.ignore("rz_core_version")

    rz_core = Class(
        core_h,
        typedef="RzCore",
        struct="rz_core_t",
        rename_fields={"autocomplete": "_autocomplete", "visual": "_visual"},
    )
    rz_core.add_constructor("rz_core_new")
    rz_core.add_destructor("rz_core_free")

    # Ignore format string functions
    core_h.ignore(
        "rz_core_notify_begin",
        "rz_core_notify_done",
        "rz_core_notify_error",
        "rz_core_cmd_strf",
        "rz_core_cmdf",
        "rz_core_syscallf",
    )

    rz_core.add_method(
        "rz_core_file_open_load",
        rename="file_open_load",
        default_args={"addr": "0", "perms": "0", "write_mode": "0"},
    )
    rz_core.add_method(
        "rz_core_file_open",
        rename="file_open",
        default_args={"flags": "0", "loadaddr": "UT64_MAX"},
    )
    rz_core.add_prefixed_methods("rz_core_")
    rz_core.add_prefixed_funcs("rz_core_")

    Class(core_h, typedef="RzCoreFile")


@threaded_header("rz_flag.h")
def bind_flag(flag_h: Header) -> None:
    """
    RzFlag
    """
    flag_h.ignore("rz_flag_version")

    rz_flag_item = Class(flag_h, typedef="RzFlagItem")
    rz_flag_item.add_prefixed_methods("rz_flag_item_")

    rz_flag = Class(flag_h, typedef="RzFlag", ignore_fields={"tags"})
    rz_flag.add_prefixed_methods("rz_flag_")
    rz_flag.add_prefixed_funcs("rz_flag_")


@threaded_header("rz_hash.h")
def bind_hash(hash_h: Header) -> None:
    """
    RzHash
    """
    Class(hash_h, typedef="RzHash")  # TODO: Add functions


@threaded_header("rz_io.h")
def bind_io(io_h: Header) -> None:
    """
    RzIO
    """
    Class(io_h, typedef="RzIO", ignore_fields={"ptrace_wrap", "priv_w32dbg_wrap"})
    Class(io_h, typedef="RzIODesc")
    Class(io_h, typedef="RzIOPlugin")


@threaded_header("rz_util/rz_num.h")
def bind_num(num_h: Header) -> None:
    """
    RzNum
    """
    rz_num = Class(num_h, typedef="RzNum")
    rz_num.add_prefixed_methods("rz_num_")
    rz_num.add_prefixed_funcs("rz_num_")


@threaded_header("rz_reg.h")
def bind_reg(reg_h: Header) -> None:
    """
    RzReg
    """
    reg_h.ignore("rz_reg_version")

    rz_reg = Class(reg_h, typedef="RzReg", rename_fields={"regset": "_regset"})
    rz_reg.add_method("rz_reg_32_to_64", rename="convert_32_to_64")
    rz_reg.add_method("rz_reg_64_to_32", rename="convert_64_to_32")
    rz_reg.add_prefixed_methods("rz_reg_")
    rz_reg.add_prefixed_funcs("rz_reg_")


@threaded_header("rz_type.h")
def bind_type(type_h: Header) -> None:
    """
    RzType
    """
    type_h.ignore("rz_type_version")
    rz_type = Class(type_h, typedef="RzType", rename_fields={"kind": "_kind"})
    rz_type.add_prefixed_methods("rz_type_")
    rz_type.add_prefixed_funcs("rz_type_")


@threaded_header("rz_types.h")
def bind_types(types_h: Header) -> None:
    """
    RZ_PERM_R/W/X
    """
    MacroEnum(types_h, prefix="RZ_PERM_")


#######
# SDB #
#######
@threaded_header("sdb/sdb.h")
def bind_sdb(sdb_h: Header) -> None:
    """
    sdb
    """
    Class(sdb_h, typedef="Sdb", ignore_fields={"db", "m"})


@threaded_header("sdb/ls.h")
def bind_ls(ls_h: Header) -> None:
    """
    ls
    """
    Class(ls_h, typedef="SdbList")


@threaded_header("sdb/ht_pp.h")
def bind_ht_pp(ht_pp_h: Header) -> None:
    """
    ht_pp
    """
    Class(ht_pp_h, typedef="HtPP")


@threaded_header("sdb/ht_pu.h")
def bind_ht_pu(ht_pu_h: Header) -> None:
    """
    ht_pu
    """
    Class(ht_pu_h, typedef="HtPU")


@threaded_header("sdb/ht_up.h")
def bind_ht_up(ht_up_h: Header) -> None:
    """
    ht_up
    """
    Class(ht_up_h, typedef="HtUP")


@threaded_header("sdb/ht_uu.h")
def bind_ht_uu(ht_uu_h: Header) -> None:
    """
    ht_uu
    """
    Class(ht_uu_h, typedef="HtUU")
