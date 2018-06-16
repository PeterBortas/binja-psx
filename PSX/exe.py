# Incomplete and full of bugs. Do not use for serious work yet.

import struct
import traceback

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error, log_debug, log_info, log_alert, log_warn, log_to_stderr, log_to_stdout
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.enums import SectionSemantics
from binaryninja import PluginCommand

from .find_bios_calls import run_plugin as find_bios_calls_run

# Playstation memory map (mostly iomapped control registers)
#
# Whereever I know of a symbol name used within PSXDEV it is used, but
# several addresses have no accociated symbol name, so in those cases
# I've invented one. Feel free to point out where I could use better
# names.
#
# TODO: Many of the multi channel entries should be compacted to loops
psx_memmap_constants = {
        # BIOS entry point, SYSCALL in in t1 (not actual syscall)
        # FIXME: BN has some special lifting for this?
        0xa0: "A0CALL",
        0xb0: "B0CALL",
        0xc0: "C0CALL",

        ## Hardware registers ##

        # Only available on the DTL-H2000
        0x1f802000: "DTLH2K_ATCONS_STAT", # TTY/Atcons TX/RX
        0x1f802002: "DTLH2K_ATCONS_DATA", # TTY/Atcons channel
        0x1f802004: "DTLH2K_UNKNOWN1",
        0x1f802030: "DTLH2K_IRQ10_EXPANSION", # More IRQ sources for lightgun
        0x1f802032: "DTLH2K_UNKNOWN2_IRQ",    # Maybe IRQ enable?
        0x1f802040: "DTLH2K_UNKNOWN3_DIP",    # Configures DTLH-2000 boot mode
        0x1f802044: "DTLH2K_POST_LED", # 8 bit value for POST display

        # Special
        0x1f802041: "BIOS_POST",  # 4 bit BIOS POST progress, like 80h in a PC
#       0x1f802070: "BIOS_POST2", # fiddled with by PS2 BIOS
#       0x1fa00000: "BIOS_POST3", # Similar to BIOS_POST, but used by PS2 BIOS

        # IRQ
        0x1f801070: "I_STAT", # IRQ status
        0x1f801074: "I_MASK", # IRQ mask

        # DMA
        0x1f8010f0: "DPCR",    # DMA control register
        0x1f8010f4: "DICR",    # DMA interrupt register
        0x1f801000: "D0_MADR", # DMA base address channel 0
        0x1f801010: "D1_MADR", #      - " -       channel 1
        0x1f801020: "D2_MADR", #      - " -       channel 2
        0x1f801030: "D3_MADR", #      - " -       channel 3
        0x1f801040: "D4_MADR", #      - " -       channel 4
        0x1f801050: "D5_MADR", #      - " -       channel 5
        0x1f801060: "D6_MADR", #      - " -       channel 6
        0x1f801004: "D0_BCR",  # DMA block control channel 0
        0x1f801014: "D1_BCR",  #       - " -       channel 1
        0x1f801024: "D2_BCR",  #       - " -       channel 2
        0x1f801034: "D3_BCR",  #       - " -       channel 3
        0x1f801044: "D4_BCR",  #       - " -       channel 4
        0x1f801054: "D5_BCR",  #       - " -       channel 5
        0x1f801064: "D6_BCR",  #       - " -       channel 6
        0x1f801008: "D0_CHCR", # DMA channel control channel 0
        0x1f801018: "D1_CHCR", #        - " -        channel 1
        0x1f801028: "D2_CHCR", #        - " -        channel 2
        0x1f801038: "D3_CHCR", #        - " -        channel 3
        0x1f801048: "D4_CHCR", #        - " -        channel 4
        0x1f801058: "D5_CHCR", #        - " -        channel 5
        0x1f801068: "D6_CHCR", #        - " -        channel 6
        0x1f8010f4: "DICR",    # DMA Interrupt Control Register

        # CDROM
        0x1f801800: "CDREG0",
        0x1f801801: "CDREG1",
        0x1f801802: "CDREG2",
        0x1f801803: "CDREG3",

        # GPU
        0x1f801810: "GPU_DATA",
        0x1f801814: "GPU_CTRL", # GPU control/Status
        0x1f8010a0: "D2_MADR",  # GPU DMA base address
        0x1f8010a4: "D2_BCR",   # GPU DMA block control
        0x1f8010a8: "D2_CHCR",  # GPU DMA channel control
        0x1f8010e0: "D6_MADR",  # GPU DMA base address
        0x1f8010e4: "D6_BCR",   # GPU DMA block control
        0x1f8010e8: "D6_CHCR",  # GPU DMA channel control
        0x1f8010f0: "DPCR",     # GPU DMA control register

        # Timers (aka root clocks)
        0x1f801100: "T0_VALUE",  # Current counter value for timer 0
        0x1f801110: "T1_VALUE",  #           - " -           timer 1
        0x1f801120: "T2_VALUE",  #           - " -           timer 2
        0x1f801104: "T0_MODE",   # Counter mode for timer 0
        0x1f801114: "T1_MODE",   #       - " -      timer 1
        0x1f801124: "T2_MODE",   #       - " -      timer 2
        0x1f801108: "T0_TARGET", # Counter target for timer 0
        0x1f801118: "T1_TARGET", #        - " -       timer 1
        0x1f801128: "T2_TARGET", #        - " -       timer 2

        # SPU (channel 0..23)
        0x1f801c00: "C0_VOLL", # Volume left
        0x1f801c02: "C0_VOLR", # Volume right
        0x1f801c04: "C0_PIT", # Pitch
        0x1f801c06: "C0_ADDR", # Startaddress of Sound
        0x1f801c08: "C0_MOD", # Attack/Decay/Sustain level
        0x1f801c0a: "C0_SURE", # Sustain rate, Release Rate
        0x1f801c0c: "C0_ADSR", # Current ADSR volume
        0x1f801c0e: "C0_REP", # Repeat address

        0x1f801c10: "C1_VOLL", # Volume left
        0x1f801c12: "C1_VOLR", # Volume right
        0x1f801c14: "C1_PIT", # Pitch
        0x1f801c16: "C1_ADDR", # Startaddress of Sound
        0x1f801c18: "C1_MOD", # Attack/Decay/Sustain level
        0x1f801c1a: "C1_SURE", # Sustain rate, Release Rate
        0x1f801c1c: "C1_ADSR", # Current ADSR volume
        0x1f801c1e: "C1_REP", # Repeat address

        0x1f801c20: "C2_VOLL", # Volume left
        0x1f801c22: "C2_VOLR", # Volume right
        0x1f801c24: "C2_PIT", # Pitch
        0x1f801c26: "C2_ADDR", # Startaddress of Sound
        0x1f801c28: "C2_MOD", # Attack/Decay/Sustain level
        0x1f801c2a: "C2_SURE", # Sustain rate, Release Rate
        0x1f801c2c: "C2_ADSR", # Current ADSR volume
        0x1f801c2e: "C2_REP", # Repeat address

        0x1f801c30: "C3_VOLL", # Volume left
        0x1f801c32: "C3_VOLR", # Volume right
        0x1f801c34: "C3_PIT", # Pitch
        0x1f801c36: "C3_ADDR", # Startaddress of Sound
        0x1f801c38: "C3_MOD", # Attack/Decay/Sustain level
        0x1f801c3a: "C3_SURE", # Sustain rate, Release Rate
        0x1f801c3c: "C3_ADSR", # Current ADSR volume
        0x1f801c3e: "C3_REP", # Repeat address

        0x1f801c40: "C4_VOLL", # Volume left
        0x1f801c42: "C4_VOLR", # Volume right
        0x1f801c44: "C4_PIT", # Pitch
        0x1f801c46: "C4_ADDR", # Startaddress of Sound
        0x1f801c48: "C4_MOD", # Attack/Decay/Sustain level
        0x1f801c4a: "C4_SURE", # Sustain rate, Release Rate
        0x1f801c4c: "C4_ADSR", # Current ADSR volume
        0x1f801c4e: "C4_REP", # Repeat address

        0x1f801c50: "C5_VOLL", # Volume left
        0x1f801c52: "C5_VOLR", # Volume right
        0x1f801c54: "C5_PIT", # Pitch
        0x1f801c56: "C5_ADDR", # Startaddress of Sound
        0x1f801c58: "C5_MOD", # Attack/Decay/Sustain level
        0x1f801c5a: "C5_SURE", # Sustain rate, Release Rate
        0x1f801c5c: "C5_ADSR", # Current ADSR volume
        0x1f801c5e: "C5_REP", # Repeat address

        0x1f801c60: "C6_VOLL", # Volume left
        0x1f801c62: "C6_VOLR", # Volume right
        0x1f801c64: "C6_PIT", # Pitch
        0x1f801c66: "C6_ADDR", # Startaddress of Sound
        0x1f801c68: "C6_MOD", # Attack/Decay/Sustain level
        0x1f801c6a: "C6_SURE", # Sustain rate, Release Rate
        0x1f801c6c: "C6_ADSR", # Current ADSR volume
        0x1f801c6e: "C6_REP", # Repeat address

        0x1f801c70: "C7_VOLL", # Volume left
        0x1f801c72: "C7_VOLR", # Volume right
        0x1f801c74: "C7_PIT", # Pitch
        0x1f801c76: "C7_ADDR", # Startaddress of Sound
        0x1f801c78: "C7_MOD", # Attack/Decay/Sustain level
        0x1f801c7a: "C7_SURE", # Sustain rate, Release Rate
        0x1f801c7c: "C7_ADSR", # Current ADSR volume
        0x1f801c7e: "C7_REP", # Repeat address

        0x1f801c80: "C8_VOLL", # Volume left
        0x1f801c82: "C8_VOLR", # Volume right
        0x1f801c84: "C8_PIT", # Pitch
        0x1f801c86: "C8_ADDR", # Startaddress of Sound
        0x1f801c88: "C8_MOD", # Attack/Decay/Sustain level
        0x1f801c8a: "C8_SURE", # Sustain rate, Release Rate
        0x1f801c8c: "C8_ADSR", # Current ADSR volume
        0x1f801c8e: "C8_REP", # Repeat address

        0x1f801c90: "C9_VOLL", # Volume left
        0x1f801c92: "C9_VOLR", # Volume right
        0x1f801c94: "C9_PIT", # Pitch
        0x1f801c96: "C9_ADDR", # Startaddress of Sound
        0x1f801c98: "C9_MOD", # Attack/Decay/Sustain level
        0x1f801c9a: "C9_SURE", # Sustain rate, Release Rate
        0x1f801c9c: "C9_ADSR", # Current ADSR volume
        0x1f801c9e: "C9_REP", # Repeat address

        0x1f801ca0: "C10_VOLL", # Volume left
        0x1f801ca2: "C10_VOLR", # Volume right
        0x1f801ca4: "C10_PIT", # Pitch
        0x1f801ca6: "C10_ADDR", # Startaddress of Sound
        0x1f801ca8: "C10_MOD", # Attack/Decay/Sustain level
        0x1f801caa: "C10_SURE", # Sustain rate, Release Rate
        0x1f801cac: "C10_ADSR", # Current ADSR volume
        0x1f801cae: "C10_REP", # Repeat address

        0x1f801cb0: "C11_VOLL", # Volume left
        0x1f801cb2: "C11_VOLR", # Volume right
        0x1f801cb4: "C11_PIT", # Pitch
        0x1f801cb6: "C11_ADDR", # Startaddress of Sound
        0x1f801cb8: "C11_MOD", # Attack/Decay/Sustain level
        0x1f801cba: "C11_SURE", # Sustain rate, Release Rate
        0x1f801cbc: "C11_ADSR", # Current ADSR volume
        0x1f801cbe: "C11_REP", # Repeat address

        0x1f801cc0: "C12_VOLL", # Volume left
        0x1f801cc2: "C12_VOLR", # Volume right
        0x1f801cc4: "C12_PIT", # Pitch
        0x1f801cc6: "C12_ADDR", # Startaddress of Sound
        0x1f801cc8: "C12_MOD", # Attack/Decay/Sustain level
        0x1f801cca: "C12_SURE", # Sustain rate, Release Rate
        0x1f801ccc: "C12_ADSR", # Current ADSR volume
        0x1f801cce: "C12_REP", # Repeat address

        0x1f801cd0: "C13_VOLL", # Volume left
        0x1f801cd2: "C13_VOLR", # Volume right
        0x1f801cd4: "C13_PIT", # Pitch
        0x1f801cd6: "C13_ADDR", # Startaddress of Sound
        0x1f801cd8: "C13_MOD", # Attack/Decay/Sustain level
        0x1f801cda: "C13_SURE", # Sustain rate, Release Rate
        0x1f801cdc: "C13_ADSR", # Current ADSR volume
        0x1f801cde: "C13_REP", # Repeat address

        0x1f801ce0: "C14_VOLL", # Volume left
        0x1f801ce2: "C14_VOLR", # Volume right
        0x1f801ce4: "C14_PIT", # Pitch
        0x1f801ce6: "C14_ADDR", # Startaddress of Sound
        0x1f801ce8: "C14_MOD", # Attack/Decay/Sustain level
        0x1f801cea: "C14_SURE", # Sustain rate, Release Rate
        0x1f801cec: "C14_ADSR", # Current ADSR volume
        0x1f801cee: "C14_REP", # Repeat address

        0x1f801cf0: "C15_VOLL", # Volume left
        0x1f801cf2: "C15_VOLR", # Volume right
        0x1f801cf4: "C15_PIT", # Pitch
        0x1f801cf6: "C15_ADDR", # Startaddress of Sound
        0x1f801cf8: "C15_MOD", # Attack/Decay/Sustain level
        0x1f801cfa: "C15_SURE", # Sustain rate, Release Rate
        0x1f801cfc: "C15_ADSR", # Current ADSR volume
        0x1f801cfe: "C15_REP", # Repeat address

        # FIXME: channels 16-23

        0x1f801d80: "S_VOLL", # Mainvolume left
        0x1f801d82: "S_VOLR", # Mainvolume right
        0x1f801d84: "S_REVL", # Reverberation depth left
        0x1f801d86: "S_REVR", # Reverberation depth right
        0x1f801d88: "S_ENA1", # Voice ON (0-15)
        0x1f801d88: "S_ENA2", # Voice ON (16-23)
        0x1f801d8c: "S_STP1", # Voice OFF (0-15)
        0x1f801d8e: "S_STP1", # Voice OFF (16-23)
        0x1f801d90: "S_MOD1", # Channel FM (pitch lfo) mode (0-15)
        0x1f801d92: "S_MOD2", # Channel FM (pitch lfo) mode (16-32)
        0x1f801d94: "S_NOICE1",  # Channel Noise mode (0-15)
        0x1f801d96: "S_NOICE2",  # Channel Noise mode (16-23)
        0x1f801d98: "S_REVERB1", # Channel Reverb mode (0-15)
        0x1f801d9a: "S_REVERB2", # Channel Reverb mode (16-23)
        0x1f801d9c: "S_ENABLE1", # Channel ON/OFF (0-15)                 ?
        0x1f801d9e: "S_ENABLE2", # Channel ON/OFF (16-23)                ?
        0x1f801da2: "S_REVERB_WORKAREA", # Reverb work area start
        0x1f801da4: "S_IRQ_ADDR", # Sound buffer IRQ address.
        0x1f801da6: "S_BUF_ADDR", # Sound buffer address
        0x1f801da8: "S_DATA",     # SPU data
        0x1f801daa: "SPUCNT",     # SPU control                sp0
        0x1f801dac: "S_RAMCNT",   # Sound RAM Data Transfer Control
        0x1f801dae: "SPUSTAT",    # SPU status
        0x1f801db0: "CDVOLL",     # CD volume left
        0x1f801db2: "CDVOLR",     # CD volume right
        0x1f801db4: "CDEXTL",     # Extern volume left
        0x1f801db6: "CDEXTR",     # Extern volume right
# TODO: This is probably incomplete. Go through available doc and add more
}

class PSXView(BinaryView):
	name = "PSX"
	long_name = "PSX-EXE"

        HDR_SIZE = 0x800

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
                # Playstation 1 used a little endian MIPS R3000a
                # without floating point support, but with some
                # extended instructions for triangle transformation
                # and lighting. mipsel32 will do for now.
		self.platform = Architecture['mipsel32'].standalone_platform

	@classmethod
	def is_valid_for_data(self, data):
		hdr = data.read(0, self.HDR_SIZE)
		if len(hdr) < self.HDR_SIZE:
			return False
		if hdr[0:8] != "PS-X EXE":
			return False
		log_info("PSX EXE identified")
		return True

	def init(self):
		try:
			hdr = self.parent_view.read(0, 0x800)
                        # Remember, Pythons indexer is retarded: from:(to+1)
           	        self.init_pc    = struct.unpack("<L", hdr[0x10:0x14])[0]
           	        self.text_start = struct.unpack("<L", hdr[0x18:0x1c])[0]
           	        self.text_size  = struct.unpack("<L", hdr[0x1c:0x20])[0]
           	        self.init_sp    = struct.unpack("<L", hdr[0x30:0x34])[0]
           	        self.info       = hdr[0x4c:self.HDR_SIZE]
                        # log_debug("/info: %r" % self.info)
                        log_debug("/info size: %s" % format(len(self.info), '#010x'))

			log_info("PC:   %s" % format(self.init_pc,    '#010x'))
			log_info("TEXT: %s" % format(self.text_start, '#010x'))
			log_info("SIZE: %s" % format(self.text_size,  '#010x'))
			log_info("SP:   %s" % format(self.init_sp,    '#010x'))
			log_info("info: %s" % self.info)

                        # PSX came with 2M, but the BIOS supports 8
                        # for dev machines. Supposed be multiple if
                        # 2048, but that is not required for the
                        # method used to sideload homebrew. (FIXME: Is
                        # it enforced by the BIOS? Can't remember...)
                        
                        # FIXME: this is just a sanity check. Make it
                        # check if text_start + text_size would run
                        # outside address space.
                        if(self.text_size > 0x800000):
                                log_warn("size > 8M: %d", self.text_size)
                        if(self.text_size % 2048 != 0):
                                log_warn("size not divisable by 2k")

                        text = self.parent_view.read(self.HDR_SIZE, self.text_size)
                        log_info("Actual size of aquired TEXT: %s" % format(len(text), '#010x'))
                        if( len(text) != self.text_size ):
                                log_error("Size of aquired data is not same as header-prescribed TEXT size. Truncated file?")

                        # add_auto_segment(start, length,
                        #                  data_offset, data_length, flags)
                        
                        r__  = SegmentFlag.SegmentReadable
                        rw_  = (SegmentFlag.SegmentReadable |
                                SegmentFlag.SegmentWritable)
                        rwx  = (SegmentFlag.SegmentReadable |
                                SegmentFlag.SegmentWritable |
                                SegmentFlag.SegmentExecutable)
                        r_x  = (SegmentFlag.SegmentReadable |
                                SegmentFlag.SegmentExecutable )
                        r_xc = (SegmentFlag.SegmentReadable |
                                SegmentFlag.SegmentExecutable |
                                SegmentFlag.SegmentContainsCode)
          
                        # Scratchpad RAM 1k
			self.add_auto_segment(0x9F800000, 1024, 0, 0, rwx)
			self.add_auto_section("Scratchpad", 0x9F800000, 1024)

                        # FIXME: I seem to remember most IO access as
                        # in the KSEG1 region. This wont cover that.
                        
                        # IO Ports 8k
			self.add_auto_segment(0x9F801000, 8*1024, 0, 0, rwx)
			self.add_auto_section("IO Ports",
                                              0x9F801000, 8*1024)
                        # Expansion 2 (IO Ports) 8k
			self.add_auto_segment(0x9F802000, 8*1024, 0, 0, rwx)
			self.add_auto_section("Expansion region 2 (IO Ports)",
                                              0x9F802000, 8*1024)
                        # Expansion 3 2M
			self.add_auto_segment(0x9FA00000, 0x200000, 0, 0, rwx)
			self.add_auto_section("Expansion region 3", 0x9FA00000, 0x200000)
                        # BIOS ROM 512k
			self.add_auto_segment(0x9FC00000, 512*1024, 0, 0, r_x)
			self.add_auto_section("BIOS", 0x9FC00000, 512*1024)

                        # RAM (cached address space) 2M
                        # Dividing this into pre-EXE and post-EXE
                        # space since it's the only way I've found to
                        # not have the exe zeroed out

                        # FIXME: The areas definitions overlap by one
                        # byte: Getting one missing byte in the
                        # viewer if I don't. Is BN using the wierd
                        # python semantics of ranges?
                        ramsize = 0x200000
                        prestart = 0x80000000
                        presize = (self.text_start - 0) - 0x80000000
                        if(presize > 0):
                                log_info("pre-RAM: %s - %s, size: %s" % (
                                        format(prestart, '#010x'),
                                        format(prestart+presize, '#010x'),
                                        format(presize, '#010x')) )
			        self.add_auto_segment(prestart, presize, 0, 0, rwx)
			        self.add_auto_section("RAM (pre EXE)", 0x80000000, presize)

                        # Area for the actual executable. Will overlap
                        # with RAM if it's a correct PSX-EXE
			self.add_auto_segment(self.text_start, self.text_size,
                                              self.HDR_SIZE, self.text_size,
                                              r_xc)
			self.add_auto_section("PS-X EXE", self.text_start, self.text_size)
                        # semantics = SectionSemantics.ReadOnlyCodeSectionSemantics)

                        # RAM (cached address space) 2M
                        poststart = self.text_start+self.text_size
                        postsize = (prestart+ramsize)-(self.text_start+self.text_size)
                        if(postsize > 0):
                                log_info("post-RAM: %s - %s, size: %s" % (
                                        format(poststart, '#010x'),
                                        format(poststart+postsize, '#010x'),
                                        format(postsize, '#010x')) )
                                self.add_auto_segment(poststart, postsize, 0, 0, rwx)
                                self.add_auto_section("RAM (post EXE)", poststart, postsize)

                        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.init_pc, "_start"))
                        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.init_sp, "_stack")) # default: 0x801ffff0
                        self.add_entry_point(self.init_pc)

                        # The iomapped control of devices in a PSX is
                        # high up that every time those values are
                        # used you can be pretty sure we are talking
                        # about the control registers and not some
                        # random loop counter.
                        #
                        # FIXME: With the exception of a0, b0 and
                        # c0-calls, those should be lifted in some
                        # other manner but are useful enough that they
                        # are hardcoded right now.
                        for addr, symbol in psx_memmap_constants.iteritems():
                                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, symbol))

                        PluginCommand.register('Find PSX BIOS calls',
                                               'Find PSX BIOS calls and rename them.',
                                               find_bios_calls_run)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return self.init_pc
