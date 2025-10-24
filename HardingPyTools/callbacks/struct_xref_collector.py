#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from . import callbacks
import HardingPyTools.core.struct_xrefs as struct_xrefs
import HardingPyTools.core.helper as helper
import community_base as _cb

class StructXrefCollectorVisitor(_cb._ida_hexrays.ctree_parentee_t):
    def __init__(self, cfunc, storage):
        super(StructXrefCollectorVisitor, self).__init__()
        self.__cfunc = cfunc
        self.__function_address = cfunc.entry_ea
        self.__result = {}
        self.__storage = storage

    def visit_expr(self, expression):
        # Checks if expression is reference by pointer or by value
        if expression.op == _cb._ida_hexrays.cot_memptr:
            struct_type = expression.x.type.get_pointed_object()
        elif expression.op == _cb._ida_hexrays.cot_memref:
            struct_type = expression.x.type
        else:
            return 0

        # Getting information about structure, field offset, address and one line corresponding to code
        ordinal = helper.get_ordinal(struct_type)
        field_offset = expression.m
        ea = self.__find_ref_address(expression)
        usage_type = self.__get_type(expression)

        if ea == _cb._ida_idaapi.BADADDR or not ordinal:
            _cb.log_print("Failed to parse at address {0}, ordinal - {1}, type - {2}".format(
                helper.to_hex(ea), ordinal, struct_type.dstr()
            ), arg_type="WARNING")

        one_line = self.__get_line()

        occurrence_offset = ea - self.__function_address
        xref_info = (occurrence_offset, one_line, usage_type)

        # Saving results
        if ordinal not in self.__result:
            self.__result[ordinal] = {field_offset: [xref_info]}
        elif field_offset not in self.__result[ordinal]:
            self.__result[ordinal][field_offset] = [xref_info]
        else:
            self.__result[ordinal][field_offset].append(xref_info)
        return 0

    def process(self):
        t = time.time()
        self.apply_to(self.__cfunc.body, None)
        self.__storage.update(self.__function_address - _cb.input_file.imagebase, self.__result)

        storage_mb_size = len(self.__storage) * 1.0 // 1024 ** 2
        _cb.log_print(f"Xref processing: {time.time() - t:f} seconds passed, storage size - {storage_mb_size:.2f} MB ")

    def __find_ref_address(self, cexpr):
        """ Returns most close virtual address corresponding to cexpr """

        ea = cexpr.ea
        if ea != _cb._ida_idaapi.BADADDR:
            return ea

        for p in reversed(self.parents):
            if p.ea != _cb._ida_idaapi.BADADDR:
                return p.ea

    def __get_type(self, cexpr):
        """ Returns one of the following types: 'R' - read value, 'W' - write value, 'A' - function argument"""
        child = cexpr
        for p in reversed(self.parents):
            assert p, "Failed to get type at " + helper.to_hex(self.__function_address)

            if p.cexpr.op == _cb._ida_hexrays.cot_call:
                return 'Arg'
            if not p.is_expr():
                return 'R'
            if p.cexpr.op == _cb._ida_hexrays.cot_asg:
                if p.cexpr.x == child:
                    return 'W'
                return 'R'
            child = p.cexpr

    def __get_line(self):
        for p in reversed(self.parents):
            if not p.is_expr():
                return _cb._ida_lines.tag_remove(p.print1(self.__cfunc))
        AssertionError("Parent instruction is not found")

class StructXrefCollector(callbacks.HexRaysEventHandler):
    def __init__(self):
        super(StructXrefCollector, self).__init__()

    def handle(self, event, *args):
        cfunc, level_of_maturity = args
        if level_of_maturity == _cb._ida_hexrays.CMAT_FINAL:
            StructXrefCollectorVisitor(cfunc, struct_xrefs.XrefStorage()).process()


callbacks.hx_callback_manager.register(_cb._ida_hexrays.hxe_maturity, StructXrefCollector())
