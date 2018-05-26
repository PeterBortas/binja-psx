from binaryninja import PluginCommand
from PSX import find_bios_calls,exe

exe.PSXView.register()
PluginCommand.register('Find PSX BIOS calls',
                       'Find PSX BIOS calls and rename them.',
                       find_bios_calls.run_plugin)
