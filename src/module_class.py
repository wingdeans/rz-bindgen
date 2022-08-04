"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only

Specifies a SWIG class
"""

from typing import List, Dict, Set, DefaultDict, Optional, overload
import os

from clang.wrapper import (
    CursorKind,
    Struct,
    Func,
    TypeKind,
)

from header import Header
from writer import BufferedWriter, DirectWriter
from module import rizin
from module_func import ModuleFunc, FuncKind
from module_typemap import ModuleTypemap


class ModuleClass:
    """
    Represents a SWIG class

    Contains a struct and SWIG %extend
    """

    name: str
    struct: Struct
    struct_writer: BufferedWriter
    funcs: List[ModuleFunc]

    sphinx_fields: DefaultDict[str, BufferedWriter]
    sphinx_funcs: Dict[str, ModuleFunc]
    sphinx_methods: Dict[str, ModuleFunc]

    @overload
    def __init__(
        self,
        header: Header,
        *,
        struct: str,
        rename: str,
        ignore_fields: Optional[Set[str]] = None,
        rename_fields: Optional[Dict[str, str]] = None,
    ):
        pass

    @overload
    def __init__(
        self,
        header: Header,
        *,
        typedef: str,
        rename: Optional[str] = None,
        ignore_fields: Optional[Set[str]] = None,
        rename_fields: Optional[Dict[str, str]] = None,
    ):
        pass

    def __init__(
        self,
        header: Header,
        *,
        typedef: Optional[str] = None,
        struct: Optional[str] = None,
        rename: Optional[str] = None,
        ignore_fields: Optional[Set[str]] = None,
        rename_fields: Optional[Dict[str, str]] = None,
    ):
        rizin.classes.append(self)

        # Get STRUCT_DECL cursor
        if typedef:
            assert not struct, "specify typedef or struct, not both"
            typedef_cursor = header.typedefs[typedef]
            struct_cursor = typedef_cursor.underlying_typedef_type.get_declaration()
            assert struct_cursor.kind == CursorKind.STRUCT_DECL
            rename = rename or typedef_cursor.spelling
        elif struct:
            struct_cursor = header.structs[struct]
        else:
            raise Exception("specify either typedef or struct")

        self.struct = struct_cursor
        self.struct_writer = BufferedWriter()
        self.funcs = []

        assert rename
        self.name = rename
        self.struct_writer.line(
            f"typedef struct {struct_cursor.spelling} {rename};",
            f"%rename {struct_cursor.spelling} {rename};",
        )

        # [[Docs]]
        self.sphinx_fields = DefaultDict(BufferedWriter)
        self.sphinx_funcs = {}
        self.sphinx_methods = {}

        # Fields
        self.gen_struct(
            struct_cursor, ignore_fields=ignore_fields, rename_fields=rename_fields
        )

    def add_constructor(self, header: Header, name: str) -> None:
        """
        Add function in header with specified name as class constructor
        """
        header.used.add(name)

        func = ModuleFunc(
            header.funcs[name], FuncKind.CONSTRUCTOR, name=self.struct.spelling
        )
        self.funcs.append(func)

    def add_destructor(self, header: Header, name: str) -> None:
        """
        Add function in header with specified name as class destructor
        """
        header.used.add(name)

        func = ModuleFunc(
            header.funcs[name], FuncKind.DESTRUCTOR, name=self.struct.spelling
        )
        self.funcs.append(func)

    def add_method(
        self,
        header: Header,
        name: str,
        *,
        rename: str,
        default_args: Optional[Dict[str, str]] = None,
        typemaps: Optional[List[ModuleTypemap]] = None,
    ) -> None:
        """
        Add function in header with specified name as method of class

        The first argument of the specified C function will be the class struct
        """
        header.used.add(name)
        modulefunc = ModuleFunc(
            header.funcs[name],
            FuncKind.THIS,
            name=rename,
            default_args=default_args,
            typemaps=typemaps,
        )
        self.funcs.append(modulefunc)

        # [[Docs]]
        if rizin.enable_sphinx:
            self.sphinx_funcs[rename] = modulefunc

    def add_func(
        self,
        header: Header,
        name: str,
        *,
        rename: str,
        default_args: Optional[Dict[str, str]] = None,
        typemaps: Optional[List[ModuleTypemap]] = None,
    ) -> None:
        """
        Add function in header with specified name as static function of class
        """
        header.used.add(name)
        modulefunc = ModuleFunc(
            header.funcs[name],
            FuncKind.STATIC,
            name=rename,
            default_args=default_args,
            typemaps=typemaps,
        )
        self.funcs.append(modulefunc)

        # [[Docs]]
        if rizin.enable_sphinx:
            self.sphinx_funcs[rename] = modulefunc

    def add_prefixed_methods(self, header: Header, prefix: str) -> None:
        """
        Adds functions with the specified prefix and who have $self
        as the first argument, as methods of the class
        """

        def predicate(func: Func) -> bool:
            if func.spelling in header.used:
                return False  # not used
            if not func.spelling.startswith(prefix):
                return False  # correct prefix
            if "RZ_API" not in func.attrs:
                return False  # RZ_API

            args = list(func.get_arguments())
            if len(args) == 0:
                return False

            arg = args[0]
            assert arg.kind == CursorKind.PARM_DECL

            if arg.type.kind != TypeKind.POINTER:
                return False
            return (
                arg.type.get_pointee().get_canonical().get_declaration() == self.struct
            )

        for func in filter(predicate, header.funcs.values()):
            header.used.add(func.spelling)

            rename = func.spelling[len(prefix) :]
            modulefunc = ModuleFunc(func, FuncKind.THIS, name=rename)
            self.funcs.append(modulefunc)

            # [[Doc]]
            if rizin.enable_sphinx:
                self.sphinx_funcs[rename] = modulefunc

    def add_prefixed_funcs(self, header: Header, prefix: str) -> None:
        """
        Adds functions with the specified prefix as static methods of the class
        """

        def predicate(func: Func) -> bool:
            if func.spelling in header.used:
                return False  # not used
            if not func.spelling.startswith(prefix):
                return False  # correct prefix
            if "RZ_API" not in func.attrs:
                return False  # RZ_API
            return True

        for func in filter(predicate, header.funcs.values()):
            header.used.add(func.spelling)

            rename = func.spelling[len(prefix) :]
            modulefunc = ModuleFunc(func, FuncKind.STATIC, name=rename)
            self.funcs.append(modulefunc)

            # [[Doc]]
            if rizin.enable_sphinx:
                self.sphinx_funcs[rename] = modulefunc

    def gen_struct(
        self,
        struct: Struct,
        *,
        ignore_fields: Optional[Set[str]] = None,
        rename_fields: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Generates the struct portion of the class, writing into the struct_writer
        BufferedWriter. This is done early so that generic fields can be specialized.
        """
        fields = set()  # ensure all ignore/rename_fields are valid
        ignore_set = ignore_fields or set()
        writer = self.struct_writer

        # %rename fields
        rename_fields = rename_fields or {}
        for old, new in rename_fields.items():
            writer.line(f"%rename {struct.spelling}::{old} {new};")

        writer.line(f"struct {struct.spelling} {{")
        with writer.indent():
            for field in struct.get_children():
                if field.kind == CursorKind.FIELD_DECL:
                    assert field.spelling not in fields
                    fields.add(field.spelling)

                    if field.spelling in ignore_set:
                        continue
                    decl = rizin.stringify_decl(field, field.type)
                    writer.line(f"{decl};")

                    # [[Docs]]
                    if rizin.enable_sphinx:
                        if field.spelling in rename_fields:
                            name = rename_fields[field.spelling]
                        else:
                            name = field.spelling
                        field_type_py = rizin.stringify_type_py(field, field.type)
                        self.sphinx_fields[name].line(
                            f"   .. py:property:: {name}",
                            f"      :type: {field_type_py}",
                        )
                elif field.kind not in [CursorKind.STRUCT_DECL, CursorKind.UNION_DECL]:
                    raise Exception(
                        f"Unexpected struct child of kind: {field.kind} at {field.location}"
                    )
        writer.line("};")

        # sanity check
        for ignored_field in ignore_set:
            assert ignored_field in fields
        for renamed_field in rename_fields.keys():
            assert renamed_field in fields

        # un %rename fields
        for old in rename_fields.keys():
            writer.line(f'%rename {struct.spelling}::{old} "";')

    def write(self, writer: DirectWriter) -> None:
        """
        Writes self to DirectWriter
        """
        self.struct_writer.write(writer)

        writer.line(f"%extend {self.struct.spelling} {{")
        with writer.indent():
            for func in self.funcs:
                func.write(writer)
        writer.line("}")

    def write_sphinx(self, path: str) -> None:
        """
        Writes class documentation to <output>/sphinx/<self.name>.rst
        """
        with open(
            os.path.join(path, f"{self.name}.rst"), "w", encoding="utf-8"
        ) as output:
            writer = DirectWriter(output)
            writer.line(self.name, "=" * len(self.name))  # Title
            writer.line(".. py:class:: " + self.name)
            writer.line("")

            for field_name in self.sphinx_fields:
                self.sphinx_fields[field_name].write(writer)
                writer.line("")

            for _, func in sorted(self.sphinx_funcs.items()):
                func.sphinx.write(writer)
                writer.line("")

            for _, method in sorted(self.sphinx_methods.items()):
                method.sphinx.write(writer)
                writer.line("")
