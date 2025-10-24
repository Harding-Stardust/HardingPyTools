#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import idaapi
from . import actions
from HardingPyTools.core.temporary_structure import VirtualTable

_G_PLUGIN_NAME = "HardingPyTools"

class CreateVtable(actions.Action):
    description = f"Create Virtual Table    [{_G_PLUGIN_NAME}]"
    hotkey = "V"

    def __init__(self):
        super(CreateVtable, self).__init__()

    @staticmethod
    def check(ea):
        return ea != idaapi.BADADDR and VirtualTable.check_address(ea)

    def activate(self, ctx):
        ea = ctx.cur_ea
        if self.check(ea):
            vtable = VirtualTable(0, ea)
            vtable.import_to_structures(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            if self.check(ctx.cur_ea):
                idaapi.attach_action_to_popup(ctx.widget, None, self.name)
                return idaapi.AST_ENABLE
            idaapi.detach_action_from_popup(ctx.widget, self.name)
            return idaapi.AST_DISABLE
        return idaapi.AST_DISABLE_FOR_WIDGET


actions.action_manager.register(CreateVtable())
