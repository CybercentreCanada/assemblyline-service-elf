import lief

section_flags_entries = {entry.__int__(): entry for entry, txt in lief.ELF.SECTION_FLAGS.__entries.values()}
segment_flags_entries = {entry.__int__(): entry for entry, txt in lief.ELF.SEGMENT_FLAGS.__entries.values()}


def get_powers(x):
    if x == 0:
        return [0]
    powers = []
    i = 1
    while i <= x:
        if i & x:
            powers.append(i)
        i <<= 1
    return powers


def extract_fn(fn):
    return {
        "address": fn.address,
        "name": fn.name,
        "size": fn.size,
        "value": fn.value,
    }


def extract_symbol(symbol):
    symbol_struct = {
        "binding": symbol.binding.name,
        "name": symbol.name,
        "type": symbol.type.name,
        "exported": symbol.exported,
        "imported": symbol.imported,
        "visibility": symbol.visibility.name,
    }
    if symbol.name != symbol.demangled_name:
        symbol_struct["demangled_name"] = symbol.demangled_name
    return symbol_struct


class AL_ELF:
    def __init__(
        self,
        data=None,
        binary=None,
        extract_relocations=False,
        extract_symbols=False,
        extract_functions=False,
    ):
        if data is not None:
            self.__dict__.update(data)
            return

        self.ctor_functions = [extract_fn(fn) for fn in binary.ctor_functions]
        self.dtor_functions = [extract_fn(fn) for fn in binary.dtor_functions]

        self.dynamic_entries = [
            {
                "tag": entry.tag.name,
                "value": entry.value,
            }
            for entry in binary.dynamic_entries
        ]

        if extract_symbols:
            self.dynamic_symbols = [extract_symbol(symbol) for symbol in binary.dynamic_symbols]
            self.exported_symbols = [extract_symbol(symbol) for symbol in binary.exported_symbols]
            self.imported_symbols = [extract_symbol(symbol) for symbol in binary.imported_symbols]
            self.static_symbols = [extract_symbol(symbol) for symbol in binary.static_symbols]
            # binary.symbols contains both static and dynamic symbols

        if extract_functions:
            self.exported_functions = [extract_fn(fn) for fn in binary.exported_functions]
            self.functions = [extract_fn(fn) for fn in binary.functions]
            self.imported_functions = [extract_fn(fn) for fn in binary.imported_functions]

        if extract_relocations:
            # TODO: Find one and work on it.
            self.dynamic_relocations = [{"purpose": entry.purpose.name} for entry in binary.dynamic_relocations]
            self.object_relocations = {}
            self.pltgot_relocations = {}
            self.relocations = {}

        self.entrypoint = binary.entrypoint
        self.format = binary.format.name
        if binary.use_gnu_hash:
            self.gnu_hash = {
                "bloom_filters": binary.gnu_hash.bloom_filters,
                "buckets": binary.gnu_hash.buckets,
                "hash_values": binary.gnu_hash.hash_values,
                "nb_buckets": binary.gnu_hash.nb_buckets,
                "shift2": binary.gnu_hash.shift2,
                "symbol_index": binary.gnu_hash.symbol_index,
            }

        if binary.has_interpreter:
            self.interpreter = binary.interpreter

        if binary.has_notes:
            self.notes = []
            for note in binary.notes:
                note_struct = {
                    "description": note.description,
                    "is_android": note.is_android,
                    "is_core": note.is_core,
                    "name": note.name,
                    "type": note.type.name,
                    "type_core": note.type_core.name,
                }
                if isinstance(note.details, lief.ELF.NoteAbi):
                    note_struct["details"] = {
                        "abi": note.details.abi.name,
                        "version": note.details.version,
                    }
                self.notes.append(note_struct)

        self.nx = binary.has_nx

        self.header = {
            "arm_flags_list": [flag.name for flag in binary.header.arm_flags_list],
            "entrypoint": binary.header.entrypoint,
            "file_type": binary.header.file_type.name,
            "header_size": binary.header.header_size,
            "hexagon_flags_list": [flag.name for flag in binary.header.hexagon_flags_list],
            "identity": binary.header.identity,
            "identity_abi_version": binary.header.identity_abi_version,
            "identity_class": binary.header.identity_class.name,
            "identity_data": binary.header.identity_data.name,
            "identity_os_abi": binary.header.identity_os_abi.name,
            "identity_version": binary.header.identity_version.name,
            "machine_type": binary.header.machine_type.name,
            "mips_flags_list": [flag.name for flag in binary.header.mips_flags_list],
            "numberof_sections": binary.header.numberof_sections,
            "numberof_segments": binary.header.numberof_segments,
            "object_file_version": binary.header.object_file_version.name,
            "ppc64_flags_list": [flag.name for flag in binary.header.ppc64_flags_list],
            "processor_flag": binary.header.processor_flag,
            "program_header_offset": binary.header.program_header_offset,
            "program_header_size": binary.header.program_header_size,
            "section_header_offset": binary.header.section_header_offset,
            "section_header_size": binary.header.section_header_size,
            "section_name_table_idx": binary.header.section_name_table_idx,
        }

        self.imagebase = binary.imagebase

        self.position_independent = binary.is_pie
        self.last_offset_section = binary.last_offset_section
        self.last_offset_segment = binary.last_offset_segment
        self.libraries = binary.libraries
        self.name = binary.name
        self.next_virtual_address = binary.next_virtual_address
        self.overlay = bytearray(binary.overlay).hex()
        self.sections = []

        for section in binary.sections:
            section_struct = {
                "alignment": section.alignment,
                # "content": section.content,
                "entropy": section.entropy,
                "entry_size": section.entry_size,
                "file_offset": section.file_offset,
                "flags_list": [flag.name for flag in section.flags_list],
                "information": section.information,
                "link": section.link,
                "name": section.name,
                "name_idx": section.name_idx,
                "offset": section.offset,
                "original_size": section.original_size,
                "segments": [segment.type.name for segment in section.segments],
                "size": section.size,
                "type": section.type.name,
                "virtual_address": section.virtual_address,
            }
            try:
                section_struct["flags"] = (
                    " | ".join([section_flags_entries[x].name for x in get_powers(section.flags.__int__())]),
                )
            except KeyError:
                pass
            self.sections.append(section_struct)

        self.segments = []
        for segment in binary.segments:
            segment_dict = {
                "alignment": segment.alignment,
                # "content": segment.content,
                "file_offset": segment.file_offset,
                "flags": "".join([segment_flags_entries[x].name for x in get_powers(segment.flags.__int__())][::-1]),
                "physical_address": segment.physical_address,
                "physical_size": segment.physical_size,
                "sections": [section.name for section in segment.sections],
                "type": segment.type.name,
                "virtual_address": segment.virtual_address,
                "virtual_size": segment.virtual_size,
            }
            try:
                segment_dict["flags"] = (
                    "".join([segment_flags_entries[x].name for x in get_powers(segment.flags.__int__())][::-1]),
                )
            except KeyError:
                pass
            self.segments.append(segment_dict)

        self.strings = binary.strings

        self.symbols_version = []
        for sv in binary.symbols_version:
            sv_struct = {
                "value": sv.value,
            }
            if sv.has_auxiliary_version:
                sv_struct["symbol_version_auxiliary"] = sv.symbol_version_auxiliary.name
            self.symbols_version.append(sv_struct)

        self.symbols_version_definition = [
            {
                "auxiliary_symbols": [{"name": aux_s.name} for aux_s in svd.auxiliary_symbols],
                "flags": svd.flags,
                "hash": svd.hash,
                "version": svd.version,
            }
            for svd in binary.symbols_version_definition
        ]

        self.symbols_version_requirement = [
            {
                "auxiliary_symbols": [{"name": aux_s.name} for aux_s in svd.get_auxiliary_symbols()],
                "name": svd.name,
                "version": svd.version,
            }
            for svd in binary.symbols_version_requirement
        ]

        if binary.use_sysv_hash:
            # TODO: Verify why len(bucket) != nbucket and len(chains) != nchain
            self.sysv_hash = {
                "buckets": binary.sysv_hash.buckets,
                "chains": binary.sysv_hash.chains,
                "nbucket": binary.sysv_hash.nbucket,
                "nchain": binary.sysv_hash.nchain,
            }
        self.type = binary.type.name
        self.virtual_size = binary.virtual_size
