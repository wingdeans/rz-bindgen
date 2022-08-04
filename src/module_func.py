"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only
"""

from typing import List, Dict, Set, Optional
from enum import Enum

from clang.wrapper import CursorKind, Func

from module import rizin
from module_typemap import ModuleTypemap
from writer import BufferedWriter, DirectWriter


class FuncKind(Enum):
    """
    Enum for ModuleFunc kind
    """

    CONSTRUCTOR = 0
    DESTRUCTOR = 1
    THIS = 2
    STATIC = 3


class ModuleFunc:
    """
    Represents a SWIG function
    """

    writer: BufferedWriter
    contract: BufferedWriter
    typemaps: List[ModuleTypemap]

    sphinx: BufferedWriter

    def __init__(
        self,
        func: Func,
        kind: FuncKind,
        *,
        name: str,
        generic_ret: bool = False,
        generic_args: Optional[Set[str]] = None,
        default_args: Optional[Dict[str, str]] = None,
        typemaps: Optional[List[ModuleTypemap]] = None,
    ):
        writer = BufferedWriter()
        self.writer = writer

        # [[Docs]]
        if rizin.enable_sphinx:
            self.sphinx = BufferedWriter()

        ### Typemaps ###
        self.typemaps = typemaps or []
        for typemap in self.typemaps:
            typemap.check(func)

        ### Args ###
        # Ignore first argument for certain types
        args = list(func.get_arguments())
        if kind in [FuncKind.DESTRUCTOR, FuncKind.THIS]:
            args = args[1:]

        # Process generics/defaults
        if generic_args is None:
            generic_args = set()
        if default_args is None:
            default_args = {}

        args_outer = []
        args_inner = []
        args_python = []

        for arg in args:
            assert arg.kind == CursorKind.PARM_DECL
            if arg.spelling == "self":
                # Rename self to _self to avoid conflict with SWIG
                arg_inner = "_self"
                arg_outer = rizin.stringify_decl(
                    arg,
                    arg.type,
                    generic=(arg.spelling in generic_args),
                    name="_self",
                )
            else:
                arg_inner = arg.spelling
                arg_outer = rizin.stringify_decl(
                    arg, arg.type, generic=(arg.spelling in generic_args)
                )
                if arg.spelling in default_args:
                    arg_outer += f" = {default_args[arg.spelling]}"

            args_inner.append(arg_inner)
            args_outer.append(arg_outer)

            # [[Docs]]
            if rizin.enable_sphinx:
                arg_python = rizin.stringify_type_py(
                    arg, arg.type, generic=(arg.spelling in generic_args)
                )
                args_python.append(f"{arg_inner}: {arg_python}")

        # Sanity check
        for generic_arg in generic_args:
            assert generic_arg in args_inner, "nonexistent generic argument specified"
        for default_arg in default_args.keys():
            assert default_arg in args_inner, "nonexistent default argument specified"

        # [[Docs]]
        if rizin.enable_sphinx:
            args_python_str = ", ".join(args_python)
            ret_python = rizin.stringify_type_py(
                func, func.result_type, generic=generic_ret
            )
            ret_python_str = f" -> {ret_python}" if ret_python else ""
            if kind == FuncKind.THIS:
                self.sphinx.line(
                    f"   .. py:method:: {name}({args_python_str}){ret_python_str}"
                )
            else:
                self.sphinx.line(
                    f"   .. py:staticmethod:: {name}({args_python_str}){ret_python_str}"
                )

            if func.spelling in rizin.doxygen_funcs:
                mappings = rizin.doxygen_funcs[func.spelling]
                links = ", ".join(
                    [f"`{filename} <doxygen/{href}>`__" for href, filename in mappings]
                )
                self.sphinx.line(
                    f"   ``{func.spelling}``: " + links,
                )

        args_outer_str = ", ".join(args_outer)
        args_inner_str = ", ".join(args_inner)

        if kind == FuncKind.CONSTRUCTOR:
            writer.line(f"{name}({args_outer_str}) {{")
        elif kind == FuncKind.DESTRUCTOR:
            args_inner_str = ", ".join(["$self"] + args_inner)
            writer.line(f"~{name}({args_outer_str}) {{")
        elif kind == FuncKind.THIS:
            args_inner_str = ", ".join(["$self"] + args_inner)
            decl = rizin.stringify_decl(
                func, func.result_type, name=name, generic=generic_ret
            )
            writer.line(f"{decl}({args_outer_str}) {{")
        elif kind == FuncKind.STATIC:
            decl = rizin.stringify_decl(
                func, func.result_type, name=name, generic=generic_ret
            )
            writer.line(f"static {decl}({args_outer_str}) {{")

        with writer.indent():
            if "RZ_DEPRECATE" in func.attrs:
                writer.line(f'rizin_try_warn_deprecate("{name}", "{func.spelling}");')

            if generic_ret:
                cast = rizin.stringify_decl(
                    func, func.result_type, name="", generic=generic_ret
                )
                writer.line(f"return ({cast}){func.spelling}({args_inner_str});")
            else:
                writer.line(f"return {func.spelling}({args_inner_str});")
        writer.line("}")

        ### Contracts ###
        contract = BufferedWriter()
        self.contract = contract

        args_nonnull = []

        for arg in args:
            if "RZ_NONNULL" in arg.attrs:
                args_nonnull.append(arg.spelling)

        if args_nonnull:
            contract.line(f"%contract {name}({args_outer_str}) {{", "require:")
            with contract.indent():
                for contract_arg in args_nonnull:
                    contract.line(f"{contract_arg} != NULL;")
            contract.line("}")

    def write(self, writer: DirectWriter) -> None:
        """
        Writes self to DirectWriter
        """
        self.contract.write(writer)

        for typemap in self.typemaps:
            typemap.write_activate(writer)

        self.writer.write(writer)

        for typemap in self.typemaps:
            typemap.write_deactivate(writer)
