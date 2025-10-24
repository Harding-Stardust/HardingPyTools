#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Fork of HexRaysPyTools that is somewhat updated for IDA 9.2
'''

__version__ = "2025-10-24 13:00:01"
__author__ = "Harding"
__description__ = __doc__
__copyright__ = "Copyright 2025"
__credits__ = ["https://github.com/oopsmishap/HexRaysPyTools",
               "https://github.com/igogo-x86/HexRaysPyTools",
               "https://github.com/Tim-Sobolev/HexRaysPyTools"]
__license__ = "GPL 3.0"
__maintainer__ = "Harding"
__email__ = "not.at.the.moment@example.com"
__status__ = "Development"
__url__ = "https://github.com/Harding-Stardust/HardingPyTools"

from pydantic import validate_call
import community_base as _cb # https://github.com/Harding-Stardust/community_base/

import HardingPyTools.core.cache as cache
import HardingPyTools.core.const as const
import HardingPyTools.settings as settings
from HardingPyTools.callbacks import hx_callback_manager, action_manager
from HardingPyTools.core.struct_xrefs import XrefStorage
from HardingPyTools.core.temporary_structure import TemporaryStructureModel

_G_PLUGIN_NAME = "HardingPyTools"

class HardingPyTools_plugmod_t(_cb._ida_idaapi.plugmod_t):
    ''' This is the code that is actually run '''
    
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __init__(self) -> None:
        action_manager.initialize()
        hx_callback_manager.initialize()
        cache.temporary_structure = TemporaryStructureModel()
        const.init()
        XrefStorage().open()
        l_addon = _cb._ida_kernwin.addon_info_t()
        l_addon.id = "Harding.HardingPyTools"
        l_addon.name = "HardingPyTools"
        l_addon.producer = __author__
        l_addon.url = __url__
        l_addon.version = __version__
        _cb._ida_kernwin.register_addon(l_addon)
        _cb.log_print(f"{_G_PLUGIN_NAME} is starting up", arg_type="INFO")
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def run(self, arg_user_argument: int) -> int:
        del arg_user_argument # never used but needed in the prototype
        return 0
    
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __del__(self) -> None:
        ''' This code is run when the user closes the IDB '''
        _cb.log_print(f"{_G_PLUGIN_NAME} is shutting down", arg_type="INFO")
        action_manager.finalize()
        hx_callback_manager.finalize()
        XrefStorage().close()
        _cb._ida_hexrays.term_hexrays_plugin()

class HardingPyTools_plugin_t(_cb._ida_idaapi.plugin_t):
    ''' This is the config for the plugin, the actual code is in the plugmod_t() '''
    flags = _cb._ida_idaapi.PLUGIN_MULTI # if this flag is set, then init have to return a ida_idaapi.plugmod_t()
    comment = "Plugin for automatic classes reconstruction (Fork of HexRaysPyTools)"
    help = "See https://github.com/Harding-Stardust/HardingPyTools/blob/master/readme.md"
    wanted_name = "HardingPyTools"
    wanted_hotkey = ""

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def init(self) -> _cb._ida_idaapi.plugmod_t:
        return HardingPyTools_plugmod_t()

def PLUGIN_ENTRY():
    settings.load_settings()
    _cb._ida_idaapi.notify_when(_cb._ida_idaapi.NW_OPENIDB, cache.initialize_cache)
    return HardingPyTools_plugin_t()
