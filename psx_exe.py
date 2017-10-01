# Incomplete and full of bugs. Do not use for serious work yet.

import struct
import traceback

import pprint

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error, log_debug, log_info, log_alert, log_warn, log_to_stderr, log_to_stdout
from binaryninja.enums import SegmentFlag, SymbolType

class PSXView(BinaryView):
	name = "PSX"
	long_name = "PSX-EXE"

        HDR_LEN = 0x800

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
                # Playstation 1 used a little endian MIPS R3000a
                # without floating point support, but with some
                # extended instructions for triangle transformation
                # and lighting. mipsel32 will do for now.
		self.platform = Architecture['mipsel32'].standalone_platform

	@classmethod
	def is_valid_for_data(self, data):
		log_info("hello PSX world")
		hdr = data.read(0, self.HDR_LEN)
		if len(hdr) < self.HDR_LEN:
			return False
		if hdr[0:8] != "PS-X EXE":
			return False
		log_info("Is PSX EXE!")
		return True

	def init(self):
                log_info("psx init")
		try:
			hdr = self.parent_view.read(0, 0x800)
                        log_info("hdr len: %d" % len(hdr))
           	        self.init_pc    = struct.unpack("<L", hdr[0x10:0x14])[0]
           	        self.text_start = struct.unpack("<L", hdr[0x18:0x1c])[0]
           	        self.text_size  = struct.unpack("<L", hdr[0x1c:0x20])[0]
           	        self.init_sp    = struct.unpack("<L", hdr[0x30:0x34])[0]
           	        self.info       = hdr[0x4c:self.HDR_LEN]

			log_info("PC:   %s" % format(self.init_pc,    '#010x'))
			log_info("TEXT: %s" % format(self.text_start, '#010x'))
			log_info("SIZE: %s" % format(self.text_size,  '#010x'))
			log_info("SP:   %s" % format(self.init_sp,    '#010x'))
			log_info("info: %s" % self.info)

                        # PSX came with 2M, but the BIOS supports 8(?)
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

                        text = self.parent_view.read(self.HDR_LEN, self.text_size)
                        log_info("Actual size of aquired TEXT: %s" % format(len(text), '#010x'))
                        if( len(text) != self.text_size ):
                                log_error("Size of aquired data is not same as header-prescribed TEXT size. Truncated file?")

          # add_auto_segment(start, length, data_offset, data_length, flags)
                        # RAM (cached address space) 2M
			self.add_auto_segment(0x8000000, 0x200000, 0, 0,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentWritable |
                                              SegmentFlag.SegmentExecutable)
                        # Scratchpad RAM 1k
			self.add_auto_segment(0x9F800000, 1024, 0, 0,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentWritable |
                                              SegmentFlag.SegmentExecutable)

                        # FIXME: I seem to remember most IO access as
                        # in the KSEG1 region. This wont cover that.
                        
                        # IO Ports 8k
			self.add_auto_segment(0x9F801000, 8*1024, 0, 0,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentWritable |
                                              SegmentFlag.SegmentExecutable)
                        # Expansion 2 (IO Ports) 8k
			self.add_auto_segment(0x9F802000, 8*1024, 0, 0,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentWritable |
                                              SegmentFlag.SegmentExecutable)
                        # Expansion 3 (IO Ports) 2M
			self.add_auto_segment(0x9FA00000, 0x200000, 0, 0,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentWritable |
                                              SegmentFlag.SegmentExecutable)
                        # BIOS ROM 512k
			self.add_auto_segment(0x9FC00000, 512*1024, 0, 0,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentExecutable)
                        
                        # BN has opinions about analyzing writable areas...
                        # SegmentFlag.SegmentWritable |
			self.add_auto_segment(self.text_start, self.text_size,
                                              self.HDR_LEN, self.text_size,
                                              SegmentFlag.SegmentReadable |
                                              SegmentFlag.SegmentExecutable)

                        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.text_start, "_start"))
                        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.init_sp, "_stack")) # default: 0x801ffff0
                        self.add_entry_point(self.text_start)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return self.init_pc

PSXView.register()
