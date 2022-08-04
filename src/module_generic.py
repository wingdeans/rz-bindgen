"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only

Specifies a generic class
"""

from typing import List, Set, DefaultDict, Optional

from clang.wrapper import CursorKind

from header import Header
from writer import DirectWriter, BufferedWriter
from module import rizin
from module_func import ModuleFunc, FuncKind


class ModuleGeneric:
    """
    Represents a generic class

    Implemented as a SWIG macro definition (eg. %RzList)
    Specializations are created by calling the macro with a type (eg. %RzList(int))
    """

    name: str
    funcs: List[ModuleFunc]
    extensions: BufferedWriter

    pointer: bool
    specializations: Set[str]
    dependencies: List[str]
    specialization_extensions: DefaultDict[str, BufferedWriter]

    def __init__(
        self,
        header: Header,
        name: str,
        *,
        pointer: bool = False,
        dependencies: Optional[List[str]] = None,
    ):
        """
        Construct a generic from a typedef
        """
        rizin.generics[name] = self  # add to mappings

        # typedef -> struct
        struct = header.typedefs[name].underlying_typedef_type.get_declaration()
        assert struct.kind == CursorKind.STRUCT_DECL
        rizin.generic_mappings[struct.spelling] = name  # add to mappings

        self.name = name
        self.funcs = []
        self.extensions = BufferedWriter()
        self.pointer = pointer
        self.specializations = set()
        self.dependencies = dependencies or []
        self.specialization_extensions = DefaultDict(BufferedWriter)

    def add_method(
        self,
        header: Header,
        name: str,
        *,
        rename: str,
        generic_ret: bool = False,
        generic_args: Optional[Set[str]] = None,
    ) -> None:
        """
        Add function in header with specified name as method of generic

        The first argument of the specified C function will be the generic struct
        generic_ret indicates whether or not the return type of the function is generic
        generic_args indicates which arguments of the function are generic
        """
        header.used.add(name)

        func = ModuleFunc(
            header.funcs[name],
            FuncKind.THIS,
            name=rename,
            generic_ret=generic_ret,
            generic_args=generic_args,
        )
        self.funcs.append(func)

    def add_extension(self, *lines: str) -> None:
        """
        Adds lines to the %extend within the generic
        """
        for line in lines:
            self.extensions.line(line)

    def add_specialization_extension(self, specialization: str, *lines: str) -> None:
        """
        Adds lines to the %extend of the specific generic specialization
        """
        for line in lines:
            self.specialization_extensions[specialization].line(line)

    def write(self, writer: DirectWriter) -> None:
        """
        Writes self to DirectWriter
        """
        writer.line(f"%define %{self.name}(TYPE)")
        with writer.indent():
            writer.line(f"%nodefaultctor {self.name}_##TYPE;")

            # The generic and its specializations are equal in C
            # eg. RzList_int == RzList
            writer.line("%{", f"typedef {self.name} {self.name}_##TYPE;", "%}")

            # Treat them differently in SWIG only
            writer.line(f"typedef struct {{}} {self.name}_##TYPE;")

            writer.line(f"%extend {self.name}_##TYPE {{")
            with writer.indent():
                for func in self.funcs:
                    func.write(writer)
                self.extensions.write(writer)
            writer.line("}")
        writer.line("%enddef")

        for specialization in self.specializations:
            for dependency in self.dependencies:
                writer.line(f"%{dependency}({specialization})")
            writer.line(f"%{self.name}({specialization})")

        for specialization, extension in self.specialization_extensions.items():
            assert specialization in self.specializations
            writer.line(f"%extend {self.name}_{specialization} {{")
            with writer.indent():
                extension.write(writer)
            writer.line("}")
