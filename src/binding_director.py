"""
SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
SPDX-License-Identifier: LGPL-3.0-only
"""

from typing import List, Dict, OrderedDict

from dataclasses import dataclass

from cparser_header import Header
from cparser_types import CType, CPointerType, CFunctionType
from binding_class import Class

directors: Dict[str, "Director"] = {}


@dataclass
class DirectorArg:
    """
    Groups a parameter cursor and its type
    """

    name: str
    ctype: CType


@dataclass
class DirectorFunc:
    """
    Groups a function cursor's args and return types
    """

    args: List[DirectorArg]
    result_ctype: CType


class Director:
    """
    A struct with function pointers that can be set from the guest language
    """

    name: str

    fields: OrderedDict[str, CType]
    funcs: OrderedDict[str, DirectorFunc]

    def __init__(self, header: Header, typedef: str):
        cls = Class(header, typedef=typedef)

        self.name = typedef
        self.fields = OrderedDict()
        self.funcs = OrderedDict()

        assert typedef not in directors
        directors[typedef] = self

        for name, field in cls.fields.items():
            if isinstance(field.ctype, CPointerType) and isinstance(
                field.ctype.pointee, CFunctionType
            ):
                ctype = field.ctype.pointee

                # arg_names should be generated in Class construction
                # when calling gen_ctype_specializations on field
                assert ctype.arg_names is not None and len(ctype.arg_names) == len(ctype.args)

                self.funcs[name] = DirectorFunc(
                    [
                        DirectorArg(arg_name, arg_ctype)
                        for arg_name, arg_ctype in zip(ctype.arg_names, ctype.args)
                    ],
                    ctype.result,
                )
            else:
                self.fields[name] = field.ctype
