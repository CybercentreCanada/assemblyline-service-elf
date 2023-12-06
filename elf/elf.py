import json
import os

import elf.al_elf
import lief
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection

# Disable logging from LIEF
lief.logging.disable()


class ELF(ServiceBase):
    def add_header(self):
        res = ResultSection("Headers")
        res.add_line(f"Entrypoint: {hex(self.elf.entrypoint)}")
        res.add_line(f"Machine: {self.elf.header['machine_type']}")
        res.add_line(f"File Type: {self.elf.header['file_type']}")
        res.add_line(f"Identity Class: {self.elf.header['identity_class']}")
        res.add_line(f"Endianness: {self.elf.header['identity_data']}")
        res.add_line(f"Virtual Size: {self.elf.virtual_size}")
        res.add_line(f"NX: {self.elf.nx}")
        res.add_line(f"Position Independent: {self.elf.position_independent}")
        res.add_line(f"Processor Flag: {self.elf.header['processor_flag']}")
        if len(self.elf.header["arm_flags_list"]) > 0:
            res.add_line(f"ARM Flags: {', '.join(self.elf.header['arm_flags_list'])}")
        if len(self.elf.header["mips_flags_list"]) > 0:
            res.add_line(f"MIPS Flags: {', '.join(self.elf.header['mips_flags_list'])}")
        if len(self.elf.header["ppc64_flags_list"]) > 0:
            res.add_line(f"PPC64 Flags: {', '.join(self.elf.header['ppc64_flags_list'])}")
        if hasattr(self.elf, "interpreter"):
            res.add_line(f"Interpreter: {self.elf.interpreter}")
            res.add_tag("file.elf.interpreter", self.elf.interpreter)

        overlay = bytes.fromhex(self.elf.overlay)
        res.add_line(f"Overlay size: {len(overlay)}")
        if len(overlay) > 0:
            file_name = "overlay"
            temp_path = os.path.join(self.working_directory, file_name)
            with open(temp_path, "wb") as myfile:
                myfile.write(overlay)
            self.request.add_extracted(
                temp_path,
                file_name,
                f"{file_name} extracted from binary's resources",
                safelist_interface=self.api_interface,
            )

        self.file_res.add_section(res)

    def add_sections(self):
        if len(self.elf.sections) == 0:
            return

        res = ResultSection("Sections")
        for section in self.elf.sections:
            sub_res = ResultSection(f"Section - {section['name']}")
            if section["name"] != "":
                sub_res.add_tag("file.elf.sections.name", section["name"])
            sub_res.add_line(f"Type: {section['type']}")
            sub_res.add_line(f"Entropy: {section['entropy']}")
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/elf.py#L447
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L363
            if section["entropy"] > 7.5:
                sub_res.set_heuristic(2)
            sub_res.add_line(f"Size: {section['size']}")
            sub_res.add_line(f"Flags: {', '.join(section['flags_list'])}")
            if len(section["segments"]):
                sub_res.add_line(f"Segments: {', '.join(section['segments'])}")
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_segments(self):
        if len(self.elf.segments) == 0:
            return

        res = ResultSection("Segments")
        for segment in self.elf.segments:
            sub_res = ResultSection(f"Segment - {segment['type']}")
            sub_res.add_line(f"Type: {segment['type']}")
            sub_res.add_tag("file.elf.segments.type", segment["type"])
            if "flags" in segment:
                sub_res.add_line(f"Flags: {segment['flags']}")
            sub_res.add_line(f"Physical Size: {segment['physical_size']}")
            sub_res.add_line(f"Virtual Size: {segment['virtual_size']}")
            if len(segment["sections"]):
                sub_res.add_line(f"Sections: {', '.join(segment['sections'])}")
            res.add_subsection(sub_res)
        if len(self.elf.segments) == 1 and self.elf.segments[0]["type"] == "LOAD" and len(self.elf.sections) == 0:
            res.set_heuristic(3)

        self.file_res.add_section(res)

    def add_libraries(self):
        # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L401
        if len(self.lief_binary.libraries) == 0:
            heur = Heuristic(8)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)
            return

        res = ResultSection("Libraries")
        for library in self.elf.libraries:
            res.add_line(library)
            res.add_tag("file.elf.libraries", library)
        self.file_res.add_section(res)

    def add_notes(self):
        if not hasattr(self.elf, "notes"):
            return
        if len(self.elf.notes) == 0:
            return

        res = ResultSection("Notes")
        for note in self.elf.notes:
            sub_res = ResultSection(f"Note - {note['name']}")
            sub_res.add_tag("file.elf.notes.name", note["name"])
            sub_res.add_line(f"Description: {note['description']}")
            sub_res.add_line(f"Type: {note['type']}")
            sub_res.add_tag("file.elf.notes.type", note["type"])
            if note["is_core"]:
                sub_res.add_line(f"Core: {note['is_core']}, {note['type_core']}")
                sub_res.add_tag("file.elf.notes.type_core", note["type_core"])
            if note["is_android"]:
                sub_res.add_line(f"Android: {note['is_android']}")
            if "details" in note:
                sub_res.add_line(f"Details: {note['details']['abi']} {'.'.join(map(str, note['details']['version']))}")
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_hash(self):
        if hasattr(self.elf, "gnu_hash"):
            res = ResultSection("GNU Hash")
            res.add_line(f"Bloom Filters: {self.elf.gnu_hash['bloom_filters']}")
            res.add_line(f"Buckets: {self.elf.gnu_hash['buckets']}")
            res.add_line(f"Hash Values: {self.elf.gnu_hash['hash_values']}")
            res.add_line(f"Number of buckets: {self.elf.gnu_hash['nb_buckets']}")
            res.add_line(f"Shift2: {self.elf.gnu_hash['shift2']}")
            res.add_line(f"Symbol Index: {self.elf.gnu_hash['symbol_index']}")
            self.file_res.add_section(res)

        if hasattr(self.elf, "sysv_hash"):
            res = ResultSection("SYSV Hash")
            res.add_line(f"Buckets: {self.elf.sysv_hash['buckets']}")
            res.add_line(f"Chains: {self.elf.sysv_hash['chains']}")
            res.add_line(f"Number of buckets: {self.elf.sysv_hash['nbucket']}")
            res.add_line(f"Number of chains: {self.elf.sysv_hash['nchain']}")
            self.file_res.add_section(res)

    # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L403
    def check_symbols(self):
        # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L426
        if not self.lief_binary.symbols:
            heur = Heuristic(9)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)
        else:
            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L782
            if not self.lief_binary.exported_symbols:
                heur = Heuristic(12)
                ResultSection(heur.name, heuristic=heur, parent=self.file_res)
            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L820
            if not self.lief_binary.imported_symbols:
                heur = Heuristic(14)
                ResultSection(heur.name, heuristic=heur, parent=self.file_res)

            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L820
            if not self.lief_binary.dynamic_symbols:
                heur = Heuristic(18)
                ResultSection(heur.name, heuristic=heur, parent=self.file_res)

            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L1560
            if not self.lief_binary.static_symbols:
                heur = Heuristic(19)
                ResultSection(heur.name, heuristic=heur, parent=self.file_res)

    # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L1064
    # and https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L1075
    def check_relocations(self):
        # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L1073
        if not self.lief_binary.object_relocations:
            heur = Heuristic(15)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)

        # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L1075
        if not self.lief_binary.relocations:
            heur = Heuristic(16)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)

    def check_dynamic_entries(self):
        # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L1538
        if not self.elf.dynamic_entries:
            heur = Heuristic(17)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)

    def add_symbols_version(self):
        # TODO: Find and example that populates at least one of:
        # symbols_version
        # symbols_version_definition
        # symbols_version_requirement
        pass

    def add_functions(self):
        if hasattr(self.elf, "imported_functions") and self.elf.imported_functions:
            res = ResultSection("Imported Functions")
            res.set_body(json.dumps(self.elf.imported_functions), BODY_FORMAT.JSON)
            self.file_res.add_section(res)
        else:
            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L798
            heur = Heuristic(13)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)
        if hasattr(self.elf, "exported_functions") and self.elf.exported_functions:
            res = ResultSection("Exported Functions")
            res.set_body(json.dumps(self.elf.exported_functions), BODY_FORMAT.JSON)
            self.file_res.add_section(res)
        else:
            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/lief.py#L760
            heur = Heuristic(11)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.request = request

        self.lief_binary = lief.parse(request.file_path)
        if self.lief_binary is None:
            res = ResultSection("This file looks like an ELF but failed loading.", heuristic=Heuristic(1))
            self.file_res.add_section(res)
            return

        self.elf = elf.al_elf.AL_ELF(
            binary=self.lief_binary,
            extract_relocations=request.deep_scan,
            extract_symbols=request.deep_scan,
            extract_functions=request.deep_scan,
        )

        self.add_header()
        self.add_sections()
        self.add_segments()
        self.add_libraries()
        self.add_notes()
        self.add_hash()
        self.check_symbols()
        self.add_symbols_version()
        self.add_functions()
        self.check_relocations()
        self.check_dynamic_entries()

        temp_path = os.path.join(self.working_directory, "features.json")
        with open(temp_path, "w") as myfile:
            myfile.write(json.dumps(self.elf.__dict__))
        request.add_supplementary(temp_path, "features.json", "Features extracted from the ELF file, as a JSON file")
