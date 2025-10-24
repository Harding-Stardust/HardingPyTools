#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# import idaapi
# import idc

from . import actions
from . import callbacks
import community_base as _cb

_G_PLUGIN_NAME = "HardingPyTools"

def inverse_if_condition(cif):
    # cexpr_t has become broken but fortunately still exist `assing` method which copies one expr into another
    cit_if_condition = cif.expr
    tmp_cexpr = _cb._ida_hexrays.cexpr_t()
    tmp_cexpr.assign(cit_if_condition)
    new_if_condition = _cb._ida_hexrays.lnot(tmp_cexpr)
    cif.expr.swap(new_if_condition)
    del cit_if_condition


def inverse_if(cif):
    inverse_if_condition(cif)
    _cb._ida_hexrays.qswap(cif.ithen, cif.ielse)

_ARRAY_STORAGE_PREFIX = "$HardingPyTools:IfThenElse:"

def has_inverted(func_ea):
    # Find if function has any swapped THEN-ELSE branches
    internal_name = _ARRAY_STORAGE_PREFIX + hex(int(func_ea - _cb.input_file.imagebase))
    internal_id = _cb._idc.get_array_id(internal_name)
    return internal_id != -1

def get_inverted(func_ea):
    # Returns set of relative virtual addresses which are tied to IF and swapped
    internal_name = _ARRAY_STORAGE_PREFIX + hex(int(func_ea - _cb.input_file.imagebase))
    internal_id = _cb._idc.get_array_id(internal_name)
    array = _cb._idc.get_array_element(_cb._idc.AR_STR, internal_id, 0)
    return set(map(int, array.split()))

def invert(func_ea, if_ea):
    # Store information about swaps (affected through actions)
    iv_rva = if_ea - _cb.input_file.imagebase
    func_rva = func_ea - _cb.input_file.imagebase
    internal_name = _ARRAY_STORAGE_PREFIX + hex(int(func_rva))
    internal_id = _cb._idc.get_array_id(internal_name)
    if internal_id == -1:
        internal_id = _cb._idc.create_array(internal_name)
        _cb._idc.set_array_string(internal_id, 0, str(iv_rva))
    else:
        inverted = get_inverted(func_ea)
        try:
            inverted.remove(iv_rva)
            if not inverted:
                _cb._idc.delete_array(internal_id)

        except KeyError:
            inverted.add(iv_rva)

        _cb._idc.set_array_string(internal_id, 0, " ".join(map(str, inverted)))


class SwapThenElse(actions.HexRaysPopupAction):
    description = f" Swap then/else    [{_G_PLUGIN_NAME}]"
    hotkey = "Shift+Alt+S" # Shift+S is now "Split Variable"

    def __init__(self):
        super(SwapThenElse, self).__init__()

    def check(self, hx_view):
        # Checks if we clicked on IF and this if has both THEN and ELSE branches
        if hx_view.item.citype != _cb._ida_hexrays.VDI_EXPR:
            return False
        insn = hx_view.item.it.to_specific_type
        if insn.op != _cb._ida_hexrays.cit_if or insn.cif.ielse is None:
            return False
        return insn.op == _cb._ida_hexrays.cit_if and insn.cif.ielse

    def activate(self, ctx):
        hx_view = _cb._ida_hexrays.get_widget_vdui(ctx.widget)
        if self.check(hx_view):
            insn = hx_view.item.it.to_specific_type
            inverse_if(insn.cif)
            hx_view.refresh_ctext()

            invert(hx_view.cfunc.entry_ea, insn.ea)

    def update(self, ctx):
        if ctx.widget_type == _cb._ida_kernwin.BWN_PSEUDOCODE:
            return _cb._ida_kernwin.AST_ENABLE_FOR_WIDGET
        return _cb._ida_kernwin.AST_DISABLE_FOR_WIDGET


actions.action_manager.register(SwapThenElse())


class SwapThenElseVisitor(_cb._ida_hexrays.ctree_parentee_t):
    def __init__(self, inverted):
        super(SwapThenElseVisitor, self).__init__()
        self.__inverted = inverted

    def visit_insn(self, insn):
        if insn.op != _cb._ida_hexrays.cit_if or insn.cif.ielse is None:
            return 0

        if insn.ea in self.__inverted:
            inverse_if(insn.cif)

        return 0

    def apply_to(self, *args):
        if self.__inverted:
            super(SwapThenElseVisitor, self).apply_to(*args)


class SpaghettiVisitor(_cb._ida_hexrays.ctree_parentee_t):
    def __init__(self):
        super(SpaghettiVisitor, self).__init__()

    def visit_insn(self, instruction):
        if instruction.op != _cb._ida_hexrays.cit_block:
            return 0

        while True:
            cblock = instruction.cblock
            size = cblock.size()
            # Find block that has "If" and "return" as last 2 statements
            if size < 2:
                break

            if cblock.at(size - 2).op != _cb._ida_hexrays.cit_if:
                break

            cif = cblock.at(size - 2).cif
            if cblock.back().op != _cb._ida_hexrays.cit_return or cif.ielse:
                break

            cit_then = cif.ithen

            # Skip if only one (not "if") statement in "then" branch
            if cit_then.cblock.size() == 1 and cit_then.cblock.front().op != _cb._ida_hexrays.cit_if:
                return 0

            inverse_if_condition(cif)

            # Take return from list of statements and later put it back
            cit_return = _cb._ida_hexrays.cinsn_t()
            cit_return.assign(instruction.cblock.back())
            cit_return.thisown = False
            instruction.cblock.pop_back()

            # Fill main block with statements from "Then" branch
            while cit_then.cblock:
                instruction.cblock.push_back(cit_then.cblock.front())
                cit_then.cblock.pop_front()

            # Put back main return if there's no another return or "GOTO" already
            if instruction.cblock.back().op not in (_cb._ida_hexrays.cit_return, _cb._ida_hexrays.cit_goto):
                new_return = _cb._ida_hexrays.cinsn_t()
                new_return.thisown = False
                new_return.assign(cit_return)
                instruction.cblock.push_back(new_return)

            # Put return into "Then" branch
            cit_then.cblock.push_back(cit_return)
        return 0


class SilentIfSwapper(callbacks.HexRaysEventHandler):

    def __init__(self):
        super(SilentIfSwapper, self).__init__()

    def handle(self, event, *args):
        cfunc, level_of_maturity = args
        if level_of_maturity == _cb._ida_hexrays.CMAT_TRANS1 and has_inverted(cfunc.entry_ea):
            # Make RVA from VA of IF instructions that should be inverted
            inverted = [n + _cb.input_file.imagebase for n in get_inverted(cfunc.entry_ea)]
            visitor = SwapThenElseVisitor(inverted)
            visitor.apply_to(cfunc.body, None)
        elif level_of_maturity == _cb._ida_hexrays.CMAT_TRANS2:
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)


callbacks.hx_callback_manager.register(_cb._ida_hexrays.hxe_maturity, SilentIfSwapper())
