import json
import os
from io import BytesIO

import lief
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    GraphSectionBody,
    Heuristic,
    OrderedKVSectionBody,
    Result,
    ResultMultiSection,
    ResultSection,
)


def bytes_to_backslashreplace_utf8_str(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    return value


def get_lief_enum_name(enum):
    try:
        return enum.name
    except (AttributeError, ValueError):
        return str(enum)


def extract_fn(fn):
    return {
        "address": fn.address,
        "name": bytes_to_backslashreplace_utf8_str(fn.name),
        "size": fn.size,
        "value": fn.value,
    }


def extract_symbol(symbol):
    symbol_struct = {
        "binding": get_lief_enum_name(symbol.binding),
        "name": bytes_to_backslashreplace_utf8_str(symbol.name),
        "type": get_lief_enum_name(symbol.type),
        "exported": symbol.exported,
        "imported": symbol.imported,
        "visibility": get_lief_enum_name(symbol.visibility),
    }
    if symbol.name != symbol.demangled_name:
        symbol_struct["demangled_name"] = bytes_to_backslashreplace_utf8_str(symbol.demangled_name)
    return symbol_struct


def extract_gnu_property(prop):
    prop_struct = {"type": prop.type.name}
    if isinstance(prop, lief.ELF.X86Features):
        prop_struct["features"] = [{"flag": flag.name, "feature": feature.name} for flag, feature in prop.features]
    elif isinstance(prop, lief.ELF.X86ISA):
        prop_struct["values"] = [{"flag": flag.name, "isa": isa.name} for flag, isa in prop.values]
    elif isinstance(prop, lief.ELF.AArch64Feature):
        prop_struct["features"] = [feature.name for feature in prop.features]
    elif isinstance(prop, lief.ELF.StackSize):
        prop_struct["stack_size"] = prop.stack_size
    elif isinstance(prop, lief.ELF.Needed):
        prop_struct["needs"] = [need.name for need in prop.needs]
    return prop_struct


def extract_note(note):
    # Extract a note and the specific fields into the details key.
    note_struct = {
        "description": bytes(note.description).hex(),
        "name": "",
        "type": get_lief_enum_name(note.type),
        "original_type": note.original_type,
    }

    try:
        note_struct["name"] = bytes_to_backslashreplace_utf8_str(note.name)
    except UnicodeDecodeError:
        note_struct.pop("name", None)

    if isinstance(note, lief.ELF.NoteAbi):
        if note.abi is not None and note.version is not None:
            note_struct["details"] = {
                "abi": get_lief_enum_name(note.abi),
                "version": note.version,
            }
    elif isinstance(note, lief.ELF.NoteGnuProperty):
        note_struct["details"] = {"properties": [extract_gnu_property(prop) for prop in note.properties]}
    elif isinstance(note, lief.ELF.CorePrPsInfo):
        if note.info is not None:
            note_struct["details"] = {
                "filename": bytes_to_backslashreplace_utf8_str(note.info.filename_stripped),
                "args": bytes_to_backslashreplace_utf8_str(note.info.args_stripped),
                "pid": note.info.pid,
                "ppid": note.info.ppid,
                "pgrp": note.info.pgrp,
                "uid": note.info.uid,
                "gid": note.info.gid,
            }
    elif isinstance(note, lief.ELF.CorePrStatus):
        status = note.status
        note_struct["details"] = {
            "pid": status.pid,
            "ppid": status.ppid,
            "cursig": status.cursig,
            "pc": note.pc,
            "sp": note.sp,
        }
    elif isinstance(note, lief.ELF.CoreFile):
        note_struct["details"] = {
            "files": [
                {
                    "path": bytes_to_backslashreplace_utf8_str(entry.path),
                    "start": entry.start,
                    "end": entry.end,
                }
                for entry in note.files
            ]
        }
    elif isinstance(note, lief.ELF.CoreSigInfo):
        note_struct["details"] = {
            "signo": note.signo,
            "sigcode": note.sigcode,
            "sigerrno": note.sigerrno,
        }

    return note_struct


class ELF(ServiceBase):
    def add_header(self):
        self.features["entrypoint"] = self.binary.entrypoint
        self.features["format"] = self.binary.format.name
        self.features["nx"] = self.binary.has_nx
        self.features["header"] = {
            "flags_list": [flag.name for flag in self.binary.header.flags_list],
            "entrypoint": self.binary.header.entrypoint,
            "file_type": get_lief_enum_name(self.binary.header.file_type),
            "header_size": self.binary.header.header_size,
            "identity": list(self.binary.header.identity),
            "identity_abi_version": self.binary.header.identity_abi_version,
            "identity_class": get_lief_enum_name(self.binary.header.identity_class),
            "identity_data": get_lief_enum_name(self.binary.header.identity_data),
            "identity_os_abi": get_lief_enum_name(self.binary.header.identity_os_abi),
            "identity_version": get_lief_enum_name(self.binary.header.identity_version),
            "machine_type": get_lief_enum_name(self.binary.header.machine_type),
            "numberof_sections": self.binary.header.numberof_sections,
            "numberof_segments": self.binary.header.numberof_segments,
            "object_file_version": get_lief_enum_name(self.binary.header.object_file_version),
            "processor_flag": self.binary.header.processor_flag,
            "program_header_offset": self.binary.header.program_header_offset,
            "program_header_size": self.binary.header.program_header_size,
            "section_header_offset": self.binary.header.section_header_offset,
            "section_header_size": self.binary.header.section_header_size,
            "section_name_table_idx": self.binary.header.section_name_table_idx,
        }
        self.features["imagebase"] = self.binary.imagebase
        self.features["is_targeting_android"] = self.binary.is_targeting_android
        self.features["page_size"] = self.binary.page_size
        self.features["eof_offset"] = self.binary.eof_offset
        self.features["position_independent"] = self.binary.is_pie
        self.features["last_offset_section"] = self.binary.last_offset_section
        self.features["last_offset_segment"] = self.binary.last_offset_segment
        self.features["next_virtual_address"] = self.binary.next_virtual_address
        self.features["type"] = get_lief_enum_name(self.binary.type)
        self.features["virtual_size"] = self.binary.virtual_size

        res = ResultSection("Headers")
        res.add_line(f"Entrypoint: {hex(self.features['entrypoint'])}")
        res.add_line(f"Machine: {self.features['header']['machine_type']}")
        res.add_line(f"File Type: {self.features['header']['file_type']}")
        res.add_line(f"Identity Class: {self.features['header']['identity_class']}")
        res.add_line(f"Endianness: {self.features['header']['identity_data']}")
        res.add_line(f"Virtual Size: {self.features['virtual_size']}")
        res.add_line(f"NX: {self.features['nx']}")
        res.add_line(f"Position Independent: {self.features['position_independent']}")
        res.add_line(f"Processor Flag: {self.features['header']['processor_flag']}")
        if len(self.features["header"]["flags_list"]) > 0:
            res.add_line(f"Processor Flags: {', '.join(self.features['header']['flags_list'])}")
        if self.features["is_targeting_android"]:
            res.add_line("Targeting Android: True")

        if self.binary.has_interpreter:
            self.features["interpreter"] = bytes_to_backslashreplace_utf8_str(self.binary.interpreter)
            res.add_line(f"Interpreter: {self.features['interpreter']}")
            res.add_tag("file.elf.interpreter", self.features["interpreter"])
            # The interpreter of standard toolchains lives in /lib*, e.g. /lib64/ld-linux-x86-64.so.2,
            # /lib/ld-musl-x86_64.so.1, /system/bin/linker64 (Android). Anything else (relative path,
            # /tmp, a regular library, ...) means execution starts in attacker-chosen code.
            interpreter = self.features["interpreter"].rstrip("\x00")
            interpreter_name = interpreter.rsplit("/", 1)[-1]
            if not (
                interpreter.startswith(("/lib", "/usr/lib", "/system/bin/", "/apex/"))
                and ("ld" in interpreter_name or "linker" in interpreter_name)
            ):
                anomaly_res = ResultSection("Non-standard program interpreter", parent=res)
                anomaly_res.add_line(f"Interpreter: {interpreter}")

        self.file_res.add_section(res)

    def add_overlay(self):
        overlay = bytes(self.binary.overlay)

        res = ResultMultiSection("Overlay", parent=self.file_res)
        entropy, partitioned_entropy = calculate_partition_entropy(BytesIO(overlay))
        overlay_kv_body = OrderedKVSectionBody()
        overlay_kv_body.add_item("Size", len(overlay))
        overlay_kv_body.add_item("Entropy", entropy)
        res.add_section_part(overlay_kv_body)
        if len(overlay) == 0:
            return

        overlay_graph_body = GraphSectionBody()
        overlay_graph_body.set_colormap(cmap_min=0, cmap_max=8, values=[round(x, 5) for x in partitioned_entropy])
        res.add_section_part(overlay_graph_body)

        file_name = "overlay"
        temp_path = os.path.join(self.working_directory, file_name)
        with open(temp_path, "wb") as myfile:
            myfile.write(overlay)
        self.request.add_extracted(
            temp_path,
            file_name,
            f"{file_name} extracted from binary",
            safelist_interface=self.api_interface,
        )

        # Droppers can append their payload after the last section/segment: check if the overlay itself is an executable
        nested = lief.ELF.parse(overlay) or lief.PE.parse(overlay)
        if nested is not None:
            nested_res = ResultSection(
                f"The overlay is itself a{'n ELF' if isinstance(nested, lief.ELF.Binary) else ' PE'} binary",
                parent=res,
            )
            nested_res.add_line("The extracted overlay will be analyzed as its own submission.")

    def add_sections(self):
        self.features["sections"] = []
        if len(self.binary.sections) == 0:
            return

        res = ResultSection("Sections")
        for section in self.binary.sections:
            section_struct = {
                "alignment": section.alignment,
                # "content": section.content,
                "entropy": section.entropy,
                "entry_size": section.entry_size,
                "file_offset": section.file_offset,
                "flags_list": [flag.name for flag in section.flags_list],
                "fullname": bytes_to_backslashreplace_utf8_str(section.fullname),
                "information": section.information,
                "link": section.link,
                "name": bytes_to_backslashreplace_utf8_str(section.name),
                "offset": section.offset,
                "original_size": section.original_size,
                "segments": [get_lief_enum_name(segment.type) for segment in section.segments],
                "size": section.size,
                "type": get_lief_enum_name(section.type),
                "virtual_address": section.virtual_address,
            }
            self.features["sections"].append(section_struct)

            sub_res = ResultMultiSection(f"Section - {section_struct['name']}")
            if section_struct["name"] != "":
                sub_res.add_tag("file.elf.sections.name", section_struct["name"])
            section_kv_body = OrderedKVSectionBody()
            section_kv_body.add_item("Type", section_struct["type"])
            section_kv_body.add_item("Entropy", section_struct["entropy"])
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/elf.py#L447
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L363
            if section_struct["entropy"] > 7.5:
                sub_res.set_heuristic(2)
            section_kv_body.add_item("Size", section_struct["size"])
            section_kv_body.add_item("Flags", ", ".join(section_struct["flags_list"]))
            if len(section_struct["segments"]):
                section_kv_body.add_item("Segments", ", ".join(section_struct["segments"]))
            sub_res.add_section_part(section_kv_body)
            _, partitioned_entropy = calculate_partition_entropy(BytesIO(bytes(section.content)))
            if partitioned_entropy:
                section_graph_body = GraphSectionBody()
                section_graph_body.set_colormap(
                    cmap_min=0, cmap_max=8, values=[round(x, 5) for x in partitioned_entropy]
                )
                sub_res.add_section_part(section_graph_body)
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_segments(self):
        self.features["segments"] = []
        if len(self.binary.segments) == 0:
            return

        res = ResultSection("Segments")
        for segment in self.binary.segments:
            segment_dict = {
                "alignment": segment.alignment,
                # "content": segment.content,
                "file_offset": segment.file_offset,
                "physical_address": segment.physical_address,
                "physical_size": segment.physical_size,
                "sections": [bytes_to_backslashreplace_utf8_str(section.name) for section in segment.sections],
                "type": get_lief_enum_name(segment.type),
                "virtual_address": segment.virtual_address,
                "virtual_size": segment.virtual_size,
                "flags": get_lief_enum_name(segment.flags),
                "raw_flags": segment.raw_flags,
            }
            self.features["segments"].append(segment_dict)

            sub_res = ResultSection(f"Segment - {segment_dict['type']}")
            sub_res.add_line(f"Type: {segment_dict['type']}")
            sub_res.add_tag("file.elf.segments.type", segment_dict["type"])
            sub_res.add_line(f"Flags: {''.join(segment_dict['flags'].split('|')[::-1])}")
            sub_res.add_line(f"Physical Size: {segment_dict['physical_size']}")
            sub_res.add_line(f"Virtual Size: {segment_dict['virtual_size']}")
            if len(segment_dict["sections"]):
                sub_res.add_line(f"Sections: {', '.join(segment_dict['sections'])}")
            res.add_subsection(sub_res)
        if (
            len(self.features["segments"]) == 1
            and self.features["segments"][0]["type"] == "LOAD"
            and len(self.features["sections"]) == 0
        ):
            res.set_heuristic(3)

        self.file_res.add_section(res)

    def add_libraries(self):
        self.features["libraries"] = [bytes_to_backslashreplace_utf8_str(library) for library in self.binary.libraries]
        if len(self.features["libraries"]) == 0:
            heur = Heuristic(4)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)
            return

        res = ResultSection("Libraries")
        for library in self.features["libraries"]:
            res.add_line(library)
            res.add_tag("file.elf.libraries", library)
        self.file_res.add_section(res)

    def add_notes(self):
        if not self.binary.has_notes:
            return
        self.features["notes"] = [extract_note(note) for note in self.binary.notes]
        if len(self.features["notes"]) == 0:
            return

        res = ResultSection("Notes")
        for note in self.features["notes"]:
            if "name" in note:
                sub_res = ResultSection(f"Note - {note['name']}")
                sub_res.add_tag("file.elf.notes.name", note["name"])
            else:
                sub_res = ResultSection("Note")
            sub_res.add_line(f"Type: {note['type']}")
            sub_res.add_tag("file.elf.notes.type", note["type"])
            description_label = "Build ID" if note["type"] == "GNU_BUILD_ID" else "Description"
            sub_res.add_line(f"{description_label}: {note['description']}")
            if note["type"].startswith("CORE_"):
                sub_res.add_line(f"Core: True, {note['type']}")
                sub_res.add_tag("file.elf.notes.type_core", note["type"])
            if note["type"].startswith("ANDROID_"):
                sub_res.add_line("Android: True")
            details = note.get("details", {})
            if "abi" in details:
                sub_res.add_line(f"Details: {details['abi']} {'.'.join(map(str, details['version']))}")
            for prop in details.get("properties", []):
                if "features" in prop and prop["type"] == "X86_FEATURE":
                    features = ", ".join(feature["feature"] for feature in prop["features"])
                    sub_res.add_line(f"x86 Features: {features}")
                elif "features" in prop:
                    sub_res.add_line(f"AArch64 Features: {', '.join(prop['features'])}")
                elif "values" in prop:
                    isas = ", ".join(f"{value['flag']} {value['isa']}" for value in prop["values"])
                    sub_res.add_line(f"x86 ISA: {isas}")
                elif "stack_size" in prop:
                    sub_res.add_line(f"Stack Size: {prop['stack_size']}")
                elif "needs" in prop:
                    sub_res.add_line(f"Needed: {', '.join(prop['needs'])}")
            if "filename" in details:
                sub_res.add_line(f"Process: {details['filename']} (args: {details['args']}, pid: {details['pid']})")
            if "files" in details:
                for entry in details["files"][:20]:
                    sub_res.add_line(f"Mapped file: {entry['path']}")
            if "signo" in details:
                sub_res.add_line(f"Signal: {details['signo']} (code: {details['sigcode']})")
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_hash(self):
        if self.binary.use_gnu_hash:
            self.features["gnu_hash"] = {
                "bloom_filters": self.binary.gnu_hash.bloom_filters,
                "buckets": self.binary.gnu_hash.buckets,
                "hash_values": self.binary.gnu_hash.hash_values,
                "nb_buckets": self.binary.gnu_hash.nb_buckets,
                "shift2": self.binary.gnu_hash.shift2,
                "symbol_index": self.binary.gnu_hash.symbol_index,
            }
            res = ResultSection("GNU Hash")
            res.add_line(f"Bloom Filters: {self.features['gnu_hash']['bloom_filters']}")
            res.add_line(f"Buckets: {self.features['gnu_hash']['buckets']}")
            res.add_line(f"Hash Values: {self.features['gnu_hash']['hash_values']}")
            res.add_line(f"Number of buckets: {self.features['gnu_hash']['nb_buckets']}")
            res.add_line(f"Shift2: {self.features['gnu_hash']['shift2']}")
            res.add_line(f"Symbol Index: {self.features['gnu_hash']['symbol_index']}")
            self.file_res.add_section(res)

        if self.binary.use_sysv_hash:
            # TODO: Verify why len(bucket) != nbucket and len(chains) != nchain
            self.features["sysv_hash"] = {
                "buckets": self.binary.sysv_hash.buckets,
                "chains": self.binary.sysv_hash.chains,
                "nbucket": self.binary.sysv_hash.nbucket,
                "nchain": self.binary.sysv_hash.nchain,
            }
            res = ResultSection("SYSV Hash")
            res.add_line(f"Buckets: {self.features['sysv_hash']['buckets']}")
            res.add_line(f"Chains: {self.features['sysv_hash']['chains']}")
            res.add_line(f"Number of buckets: {self.features['sysv_hash']['nbucket']}")
            res.add_line(f"Number of chains: {self.features['sysv_hash']['nchain']}")
            self.file_res.add_section(res)

    def add_ctor_dtor_functions(self):
        self.features["ctor_functions"] = [extract_fn(fn) for fn in self.binary.ctor_functions]
        self.features["dtor_functions"] = [extract_fn(fn) for fn in self.binary.dtor_functions]

    def add_strings(self):
        self.features["strings"] = [bytes_to_backslashreplace_utf8_str(s) for s in self.binary.strings]

    def add_symbols(self):
        if self.request.deep_scan:
            self.features["dynamic_symbols"] = [extract_symbol(symbol) for symbol in self.binary.dynamic_symbols]
            self.features["exported_symbols"] = [extract_symbol(symbol) for symbol in self.binary.exported_symbols]
            self.features["imported_symbols"] = [extract_symbol(symbol) for symbol in self.binary.imported_symbols]
            self.features["static_symbols"] = [extract_symbol(symbol) for symbol in self.binary.symtab_symbols]

        if not self.binary.symbols:
            heur = Heuristic(8)
            ResultSection(heur.name, body=heur.description, heuristic=heur, parent=self.file_res)
        elif not self.binary.dynamic_symbols:
            heur = Heuristic(6)
            ResultSection(heur.name, body=heur.description, heuristic=heur, parent=self.file_res)

    def add_symbols_version(self):
        self.features["symbols_version"] = []
        for sv in self.binary.symbols_version:
            sv_struct = {
                "value": sv.value,
            }
            if sv.has_auxiliary_version:
                sv_struct["symbol_version_auxiliary"] = bytes_to_backslashreplace_utf8_str(
                    sv.symbol_version_auxiliary.name
                )
            self.features["symbols_version"].append(sv_struct)

        self.features["symbols_version_definition"] = [
            {
                "auxiliary_symbols": [
                    {"name": bytes_to_backslashreplace_utf8_str(aux_s.name)} for aux_s in svd.auxiliary_symbols
                ],
                "flags": svd.flags,
                "hash": svd.hash,
                "version": svd.version,
            }
            for svd in self.binary.symbols_version_definition
        ]

        self.features["symbols_version_requirement"] = [
            {
                "auxiliary_symbols": [
                    {"name": bytes_to_backslashreplace_utf8_str(aux_s.name)} for aux_s in svd.get_auxiliary_symbols()
                ],
                "name": bytes_to_backslashreplace_utf8_str(svd.name),
                "version": svd.version,
            }
            for svd in self.binary.symbols_version_requirement
        ]

        # The per-symbol symbols_version table is kept in the features only: it has one entry
        # per dynamic symbol, and the interesting aggregate (which versions are used) is
        # already the auxiliary_symbols of the requirement/definition entries.
        if self.features["symbols_version_requirement"]:
            res = ResultSection("Required Symbol Versions", parent=self.file_res)
            for requirement in self.features["symbols_version_requirement"]:
                versions = ", ".join(sorted(aux["name"] for aux in requirement["auxiliary_symbols"]))
                res.add_line(f"{requirement['name']}: {versions}")

        if self.features["symbols_version_definition"]:
            res = ResultSection("Defined Symbol Versions", parent=self.file_res)
            for definition in self.features["symbols_version_definition"]:
                res.add_line(", ".join(aux["name"] for aux in definition["auxiliary_symbols"]))

    def add_functions(self):
        if not self.request.deep_scan:
            return

        self.features["exported_functions"] = [extract_fn(fn) for fn in self.binary.exported_functions]
        self.features["functions"] = [extract_fn(fn) for fn in self.binary.functions]
        self.features["imported_functions"] = [extract_fn(fn) for fn in self.binary.imported_functions]

        if self.features["imported_functions"]:
            res = ResultSection("Imported Functions")
            res.set_body(json.dumps(self.features["imported_functions"]), BODY_FORMAT.JSON)
            self.file_res.add_section(res)
        if self.features["exported_functions"]:
            res = ResultSection("Exported Functions")
            res.set_body(json.dumps(self.features["exported_functions"]), BODY_FORMAT.JSON)
            self.file_res.add_section(res)

    def add_relocations(self):
        if self.request.deep_scan:
            # Most relocations are unsymboled bulk (e.g. hundreds of X86_64_RELATIVE for PIE
            # fixups), so store a type histogram, and the full entry only when it references
            # a symbol. The symboled PLT/GOT entries are the resolved import list, a useful
            # complement to imported_functions on stripped binaries.
            group_counts = 0
            for feature, relocations in [
                ("dynamic_relocations", self.binary.dynamic_relocations),
                ("pltgot_relocations", self.binary.pltgot_relocations),
                ("object_relocations", self.binary.object_relocations),
            ]:
                types = {}
                symboled = []
                for relocation in relocations:
                    relocation_type = get_lief_enum_name(relocation.type)
                    types[relocation_type] = types.get(relocation_type, 0) + 1
                    if relocation.has_symbol and relocation.symbol.name:
                        entry = {
                            "type": relocation_type,
                            "address": relocation.address,
                            "symbol": bytes_to_backslashreplace_utf8_str(relocation.symbol.name),
                        }
                        if relocation.is_rela:
                            entry["addend"] = relocation.addend
                        symboled.append(entry)
                self.features[feature] = {"types": types, "symbols": symboled}
                group_counts += sum(types.values())

            # binary.relocations should be exactly the three groups above: anything more
            # means relocations with an unknown purpose (e.g. PURPOSE.NONE), worth surfacing
            ungrouped = len(list(self.binary.relocations)) - group_counts
            if ungrouped > 0:
                res = ResultSection("Ungrouped relocations", parent=self.file_res)
                res.add_line(
                    f"{ungrouped} relocation{'s' if ungrouped > 1 else ''} not part of the dynamic, "
                    "PLT/GOT or object relocation tables."
                )
                ungrouped_types = {}
                for relocation in self.binary.relocations:
                    if relocation.purpose == lief.ELF.Relocation.PURPOSE.NONE:
                        relocation_type = get_lief_enum_name(relocation.type)
                        ungrouped_types[relocation_type] = ungrouped_types.get(relocation_type, 0) + 1
                for relocation_type, count in sorted(ungrouped_types.items()):
                    res.add_line(f"{relocation_type}: {count}")

        if not self.binary.relocations:
            heur = Heuristic(7)
            ResultSection(heur.name, body=heur.description, heuristic=heur, parent=self.file_res)

    def add_dynamic_entries(self):
        self.features["dynamic_entries"] = []
        for entry in self.binary.dynamic_entries:
            entry_struct = {
                "tag": get_lief_enum_name(entry.tag),
                "value": entry.value,
            }
            if isinstance(entry, lief.ELF.DynamicEntryFlags):
                entry_struct["flags"] = [flag.name for flag in entry.flags]
            elif isinstance(entry, (lief.ELF.DynamicEntryLibrary, lief.ELF.DynamicSharedObject)):
                entry_struct["name"] = bytes_to_backslashreplace_utf8_str(entry.name)
            elif isinstance(entry, lief.ELF.DynamicEntryRpath):
                entry_struct["paths"] = [bytes_to_backslashreplace_utf8_str(path) for path in entry.paths]
            elif isinstance(entry, lief.ELF.DynamicEntryRunPath):
                entry_struct["paths"] = [bytes_to_backslashreplace_utf8_str(path) for path in entry.paths]
            self.features["dynamic_entries"].append(entry_struct)

        if not self.features["dynamic_entries"]:
            heur = Heuristic(5)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)
            return

        res = None
        for entry in self.features["dynamic_entries"]:
            line = None
            if "flags" in entry:
                line = f"{entry['tag']}: {', '.join(entry['flags'])}"
            elif "paths" in entry:
                line = f"{entry['tag']}: {':'.join(entry['paths'])}"
            elif entry["tag"] == "SONAME" and "name" in entry:
                line = f"{entry['tag']}: {entry['name']}"

            if line is not None:
                if res is None:
                    res = ResultSection("Dynamic Entries", parent=self.file_res)
                res.add_line(line)

    def add_lief_logging(self, lief_output_file):
        if not os.path.exists(lief_output_file):
            return

        with open(lief_output_file, "rb") as f:
            lief_output = f.readlines()

        lief_logging = {}
        for line in lief_output:
            line = line.decode("utf-8", "backslashreplace").rstrip().rstrip("\x00")
            if not line:
                continue
            lief_logging[line] = lief_logging.get(line, 0) + 1

        if not lief_logging:
            return

        res = ResultSection("LIEF logging information.", parent=self.file_res)
        corrupted_res = None
        corruption_markers = ("corrupted", "can't parse", "out of range", "failed", "can't read", "invalid")
        for line, count in lief_logging.items():
            output_line = f"({count}x) {line}" if count > 1 else line
            res.add_line(output_line)
            if any(marker in line.lower() for marker in corruption_markers):
                if corrupted_res is None:
                    corrupted_res = ResultSection("Corrupted ELF structures", parent=res)
                corrupted_res.add_line(output_line)

    def _cleanup(self):
        self.binary = None
        self.features = None
        super()._cleanup()

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.request = request

        lief_output_file = os.path.join(self.working_directory, "lief_output")
        lief.logging.set_path(lief_output_file)

        self.binary = lief.ELF.parse(request.file_path)
        if self.binary is None:
            res = ResultSection("This file looks like an ELF but failed loading.", heuristic=Heuristic(1))
            self.file_res.add_section(res)
            self.add_lief_logging(lief_output_file)
            return

        self.features = {}
        self.add_header()
        self.add_sections()
        self.add_segments()
        self.add_libraries()
        self.add_notes()
        self.add_hash()
        self.add_ctor_dtor_functions()
        self.add_strings()
        self.add_symbols()
        self.add_symbols_version()
        self.add_functions()
        self.add_relocations()
        self.add_dynamic_entries()
        self.add_overlay()
        self.add_lief_logging(lief_output_file)

        temp_path = os.path.join(self.working_directory, "features.json")
        with open(temp_path, "w") as myfile:
            myfile.write(json.dumps(self.features))
        request.add_supplementary(temp_path, "features.json", "Features extracted from the ELF file, as a JSON file")
