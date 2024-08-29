#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <elf.h>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

#include "symbolize.h"

namespace {
    using namespace symbolize;

    string sym_name(section* s, Elf32_Sym *sym) {
        return "x" + to_string(sym->st_value) + "_XD";
    }

    rel_section* rel_for(program& p, section* s) {
        assert(s->hdr->sh_type != SHT_REL);
        int s_idx = p.index_of(s);

        for (auto t : p.sections) {
            if (t->hdr->sh_type == SHT_REL && t->hdr->sh_info == s_idx)
                return static_cast<rel_section *>(t);
        }

        auto name = ".rel" + p.shstrtab->str_by_offset(s->hdr->sh_name);
        return p.add_rel_section(name, s_idx);
    }

    section* sec_for(program& p, Elf32_Addr addr) {
        for (auto s : p.sections)
            // TODO: rozmiary relokacji
            if (s->hdr->sh_addr <= addr && addr + 4 <= s->hdr->sh_addr + s->hdr->sh_size)
                return s;
        return nullptr;
    }

    optional<elf_symbol> sym_for(program const& in, program& out, int old_idx) {
        for (auto s : out.symtab->symbols)
            if (s.old_idx == old_idx)
                return s;
        Elf32_Addr old_addr = in.symtab->symbols[old_idx].symbol.st_value;
        for (auto s : out.symtab->symbols)
            if (s.symbol.st_value == old_addr)
                return s;
        return {};
    }

    void fix_segment(program const& in, program &out, Elf32_Rel in_rel, Elf32_Rel out_rel, elf_symbol& out_sym, section* outsec) {
        Elf32_Word* value = (Elf32_Word*) &outsec->data[out_rel.r_offset];
        // The value of the symbol whose index resides in the relocation entry.
        Elf32_Addr s = out_sym.symbol.st_value;
        // The section offset or address of the storage unit being relocated, computed using r_offset.
        Elf32_Off p = in_rel.r_offset;

        int type = ELF32_R_TYPE(in_rel.r_info);
        if (type == R_386_32) {
            // S + A
            // The addend used to compute the value of the relocatable field.
            int a = *value - s;
            *value = a;
        } else if (type == R_386_PC32) {
            // S + A - P
            int a =  *value - s + p;
            *value = a;
        }
    }

    void convert_rels(program const& in, program& out) {
        for (int i = 0; i < in.sections.size(); i++) {
            auto s = in.sections[i];
            if (s->hdr->sh_type != SHT_REL)
                continue;

            rel_section* reltab = (rel_section*)s;
            for (auto rel : reltab->rels) {
                auto outsec = sec_for(out, rel.r_offset);
                auto outrel = rel_for(out, outsec);
                auto outsym = sym_for(in, out, ELF32_R_SYM(rel.r_info));
                if (!outsym.has_value()) {
                    log("Relocation for unknown symbol old_idx=", ELF32_R_SYM(rel.r_info));
                    continue;
                }

                auto new_rel = Elf32_Rel{
                    .r_offset = rel.r_offset - outsec->hdr->sh_addr,
                    .r_info = ELF32_R_INFO(outsym->new_idx, ELF32_R_TYPE(rel.r_info)),
                };
                outrel->rels.push_back(new_rel);
                fix_segment(in, out, rel, new_rel, outsym.value(), outsec);
            }
        }
    }

    char get_symbol_code(string section_name, section *containing, Elf32_Sym sym) {
        char code = 'U';
        int binding = ELF32_ST_BIND(sym.st_info);
        if (sym.st_shndx == SHN_ABS)
            code = 'A';
        else if (section_name == ".bss" && binding == STB_LOCAL)
            code = 'b';
        else if (section_name == ".bss" )
            code = 'B';
        else if (section_name == ".data" && binding == STB_LOCAL)
            code = 'd';
        else if (section_name == ".data")
            code = 'D';
        else if (section_name == ".rodata" && binding == STB_LOCAL)
            code = 'r';
        else if (section_name == ".rodata")
            code = 'R';
        else if (section_name == ".text" && binding == STB_LOCAL)
            code = 't';
        else if (section_name == ".text")
            code = 'T';
        else
            code = '$';
        return code;
    }

    string symbol_name(string section_name, section *containing_section, Elf32_Sym sym) {
        std::stringstream ss;
        ss << section_name << ".x" << std::hex << std::setfill('0') << std::setw(8) << sym.st_value;
        return ss.str() + std::string(1, get_symbol_code(section_name, containing_section, sym));
    }

    void raw_move_section(section* s, const string& s_name, program& out) {
        auto sec = out.add_section(s_name);
        int name = sec->hdr->sh_name;
        *sec->hdr = *s->hdr;
        sec->hdr->sh_name = name;
        sec->hdr->sh_addr = 0;

        sec->append(s->data, s->hdr->sh_size);
    }

    void parse_progbits(program& in, program& out, section *s, const string& s_name, int shndx) {
        if (s_name == ".comment") {
            raw_move_section(s, s_name, out);
            return;
        }

        vector<elf_symbol> filtered_syms;
        std::copy_if(in.symtab->symbols.begin(), in.symtab->symbols.end(), std::back_inserter(filtered_syms), [&](elf_symbol sym) {
            string symbol_name = in.strtab->str_by_offset(sym.symbol.st_name);
            return symbol_name != "__stack";
        });

        auto syms = program::symbols_in_section_asc(s, filtered_syms, shndx);
        bool is_first = true;
        int size_sum = 0;

        for (int i = 0; i < syms.size(); i++) {
            auto sym = syms[i];
            if (sym.symbol.st_value < s->hdr->sh_addr)
                continue;
            int real_symbol_size = i+1 < syms.size()
                    ? syms[i+1].symbol.st_value - syms[i].symbol.st_value
                    : s->hdr->sh_size - size_sum;
            if (real_symbol_size == 0)
                continue;

            // symbol new name
            string name = symbol_name(s_name, s, sym.symbol);
            Elf32_Word name_off = out.strtab->last_offset();
            out.strtab->entries.push_back(name);

            Elf32_Section sec_id = out.sections.size();
            auto sec = out.add_section(name);

            sec->hdr->sh_type = s->hdr->sh_type;
            sec->hdr->sh_flags = s->hdr->sh_flags;
            sec->hdr->sh_addr = s->hdr->sh_addr + size_sum;
            if (is_first) {
                sec->hdr->sh_addralign = s->hdr->sh_addralign;
                is_first = false;
            }
            sec->hdr->sh_size = sym.symbol.st_size > 0 ? sym.symbol.st_size : real_symbol_size;

            sec->append(s->data + size_sum, sec->hdr->sh_size);
            size_sum += sec->hdr->sh_size;

            Elf32_Sym rel_sym{
                .st_name = name_off,
                .st_value = sym.symbol.st_value,
                .st_size = sec->hdr->sh_size,
                .st_info = sym.symbol.st_info,
                .st_other = sym.symbol.st_other,
                .st_shndx = sec_id,
            };
            int sidx = out.symtab->symbols.size();
            out.symtab->symbols.push_back(elf_symbol{
                .symbol = rel_sym,
                .old_idx = sym.old_idx,
                .new_idx = sidx
            });
        }
    }

    void solve(program in, string out) {
        program output{};
        output.ehdr.e_machine = in.ehdr.e_machine;
        output.ehdr.e_version = in.ehdr.e_version;
        output.init();

        int shndx = 0;
        for (auto s : in.sections) {
            // sh_align - tylko dla pierwszej sekcji w rozbijanej grupie
            // sh_entsize - dla specyficzny
            string in_section_name(&in.shstrtab->data[s->hdr->sh_name]);
            if (s->hdr->sh_type == SHT_PROGBITS) {
                parse_progbits(in, output, s, in_section_name, shndx);
            } else if (s->hdr->sh_type == SHT_NOBITS) {
                if (in_section_name != ".stack") {
                    raw_move_section(s, in_section_name, output);
                }
            }
            shndx++;
        }

        output.sort_symtabs();
        convert_rels(in, output);

        output.save(out);
    }
}

int main(int argc, char** argv) {
    if (argc < 3) {
        log_err("Usage:\n", "   ", argv[0], " <input file> <output file>");
        return 1;
    }
    log("Symbolize ", argv[1], " --> ", argv[2]);

    program prog;
    prog.load(argv[1]);
    solve(prog, argv[2]);

    return 0;
}
