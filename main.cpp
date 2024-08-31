#include <algorithm>
#include <cassert>
#include <complex>
#include <cstring>
#include <iostream>
#include <elf.h>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <vector>

#include "symbolize.h"

namespace {
    using namespace symbolize;


    char get_symbol_code(string section_name, Elf32_Sym sym) {
        char code = 'U';
        int binding = ELF32_ST_BIND(sym.st_info);
        if (sym.st_shndx == SHN_ABS)
            code = 'A';
        else if (section_name == ".bss" && binding == STB_LOCAL)
            code = 'b';
        else if (section_name == ".bss" )
            code = 'B';
        else if ((section_name == ".data" || section_name == ".got")&& binding == STB_LOCAL)
            code = 'd';
        else if (section_name == ".data" || section_name == ".got")
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

    string symbol_name(string containing_section_name, Elf32_Sym sym) {
        std::stringstream ss;
        ss << "x" << std::hex << std::setfill('0') << std::setw(8) << sym.st_value;
        ss << get_symbol_code(containing_section_name, sym);
        return ss.str();
    }

    string out_section_name(string section_name, Elf32_Addr addr) {
        std::stringstream ss;
        ss << section_name << ".x" << std::hex << std::setfill('0') << std::setw(8) << addr;
        return ss.str();
    }

    string out_section_name(string section_name, Elf32_Sym sym) {
        return section_name + "." + symbol_name(section_name, sym);
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

    void fix_segment(program& in, program &out, Elf32_Rel in_rel, Elf32_Rel out_rel, elf_symbol& out_sym, section* outsec) {
        Elf32_Word* value = (Elf32_Word*) &outsec->data[out_rel.r_offset];
        // S - The value of the symbol whose index resides in the relocation entry.
        Elf32_Addr s = out_sym.symbol.st_value;
        // P - The section offset or address of the storage unit being relocated, computed using r_offset.
        Elf32_Off p = in_rel.r_offset;
        // GOT - The address of the global offset table.
        Elf32_Off got = 0;
        // A - The addend used to compute the value of the relocatable field.
        int a = 0;
        // G - The offset into the global offset table at which the address of the relocation entry's
        //  symbol resides during execution
        int g = 0;

        if (in.got != nullptr) {
            got = in.got->hdr->sh_addr;
            g = *value; // TODO: addend?
        }

        int type = ELF32_R_TYPE(in_rel.r_info);
        if (type == R_386_32) {
            // S + A
            a = *value - s;
        } else if (type == R_386_PC32) {
            // S + A - P
            a =  *value - s + p;
        } else if (type == R_386_GOTPC) {
            a = *value - got + p;
        } else if (type == R_386_GOTOFF) {
            a = *value - s + got;
        } else if (type == R_386_GOT32) {
            a = *value - g;
        }

        *value = a;
    }

    void convert_rels(program& in, program& out) {
        auto all_reltabs = in.find_rels();
        for (auto reltab : all_reltabs) {
            for (auto rel : reltab->rels) {
                int r_sym = ELF32_R_SYM(rel.r_info);

                auto outsec = sec_for(out, rel.r_offset);
                auto outrel = rel_for(out, outsec);
                auto outsym = sym_for(in, out, r_sym);
                if (!outsym.has_value()) {
                    log("Relocation for unknown symbol old_idx=", r_sym);
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

    void raw_move_section(section* s, const string& s_name, program& out) {
        auto sec = out.add_section(s_name);
        int name = sec->hdr->sh_name;
        *sec->hdr = *s->hdr;
        sec->hdr->sh_name = name;
        sec->hdr->sh_addr = 0;

        sec->append(s->data, s->hdr->sh_size);
    }

    bool should_break_symbols_into_sections(section *s, const string& s_name) {
        if (s_name == ".comment")
            return false;
        return true;
    }

    int break_symbol_into_section(program& out, string const& sym_name, section* s, int s_data_off, bool set_align, Elf32_Word sec_size) {
        int sec_id = out.sections.size();
        auto sec = out.add_section(sym_name);

        sec->hdr->sh_type = s->hdr->sh_type;
        sec->hdr->sh_flags = s->hdr->sh_flags;
        sec->hdr->sh_addr = s->hdr->sh_addr + s_data_off;
        if (set_align)
            sec->hdr->sh_addralign = s->hdr->sh_addralign;
        sec->hdr->sh_size = sec_size;

        sec->append(s->data + s_data_off, sec->hdr->sh_size);
        return sec_id;
    }

    vector<elf_symbol> section_symbols_asc(program& in, int shndx) {
        vector<elf_symbol> sec_syms;
        std::copy_if(in.symtab->symbols.begin(), in.symtab->symbols.end(), std::back_inserter(sec_syms), [&](elf_symbol sym) {
            int t = ELF32_ST_TYPE(sym.symbol.st_info);
            return (t == STT_FUNC || t == STT_OBJECT)
                && sym.symbol.st_size > 0
                && sym.symbol.st_shndx == shndx;
        });
        sort(sec_syms.begin(), sec_syms.end(), SYMBOLS_ASC_BY_ADDR_CMP);
        return sec_syms;
    }

    // - st_value na sztywno
    // - rozmiar symboli
    void parse_file_and_mem(program& in, program& out, section *s, int shndx) {
        vector<elf_symbol> ssyms = section_symbols_asc(in, shndx);
        vector<elf_symbol> all_syms = in.symbols_in_section_asc(shndx);
        string s_name = in.shstrtab->str_by_offset(s->hdr->sh_name);
        const Elf32_Addr max_s_addr = s->hdr->sh_size + s->hdr->sh_addr;

        int ssyms_ptr = 0, all_syms_ptr = 0;
        section *current;
        int shndx_current;
        Elf32_Addr s_change_addr = s->hdr->sh_addr;
        for (int i = 0; i < s->hdr->sh_size; i++) {
            Elf32_Addr addr = s->hdr->sh_addr + i;
            bool started_new = false;

            // start a new section
            if (ssyms_ptr < ssyms.size() && ssyms[ssyms_ptr].symbol.st_value == addr) {
                elf_symbol ssym = ssyms[ssyms_ptr];
                current = out.add_section(out_section_name(s_name, ssym.symbol));

                started_new = true;
                s_change_addr = addr + ssym.symbol.st_size;
                ssyms_ptr++;
            } else if (addr == s_change_addr) {
                current = out.add_section(out_section_name(s_name, addr));

                started_new = true;
                s_change_addr = max_s_addr;
            }

            if (started_new) {
                if (i == 0) {
                    current->hdr->sh_addralign = s->hdr->sh_addralign;
                }
                current->hdr->sh_addr = addr;
                current->hdr->sh_type = s->hdr->sh_type;
                current->hdr->sh_flags = s->hdr->sh_flags;
                shndx_current = out.sections.size()-1;
            }

            // add symbols
            if (all_syms_ptr < all_syms.size() && all_syms[all_syms_ptr].symbol.st_value == addr) {
                auto in_sym = all_syms[all_syms_ptr];
                string name = symbol_name(s_name, in_sym.symbol);
                auto sym = elf_symbol{
                    .symbol = in_sym.symbol,
                    .old_idx = in_sym.old_idx,
                    .new_idx = 0,
                };
                sym.symbol.st_shndx = shndx_current;
                out.add_symbol(name, sym);
                all_syms_ptr++;
            }

            // update pointers
            current->hdr->sh_size++;
            current->append(&s->data[i], 1);
        }
    }

    void add_got_symbol_if_needed(program& in, program& out) {
        int got_idx = 0;
        // GOT symbol
        auto reltabs = in.find_rels();
        for (auto reltab : reltabs) {
            for (auto rel : reltab->rels) {
                if (ELF32_R_TYPE(rel.r_info) == R_386_GOTPC) {
                    got_idx = ELF32_R_SYM(rel.r_info);
                }
            }
        }

        if (got_idx > 0) {
            log("The file contains .got");
            elf_symbol sym{
                .symbol = Elf32_Sym{},
                .old_idx = got_idx,
            };
            auto got_sym = in.symtab->symbols[got_idx].symbol;
            sym.symbol.st_value = got_sym.st_value;
            sym.symbol.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
            out.add_symbol("_GLOBAL_OFFSET_TABLE_", sym);
        }
    }

    void solve(program in, string out) {
        program output{};
        output.ehdr.e_machine = in.ehdr.e_machine;
        output.ehdr.e_version = in.ehdr.e_version;
        output.ehdr.e_entry = in.ehdr.e_entry;
        output.init();

        int shndx = 0;
        for (auto s : in.sections) {
            // sh_align - tylko dla pierwszej sekcji w rozbijanej grupie
            // sh_entsize - dla specyficzny
            string in_section_name(&in.shstrtab->data[s->hdr->sh_name]);
            if (s->hdr->sh_type == SHT_PROGBITS) {
                if (in_section_name == ".got") {
                    // skip the section
                } else {
                    parse_file_and_mem(in, output, s, shndx);
                }
            } else if (s->hdr->sh_type == SHT_NOBITS) {
                if (in_section_name != ".stack") {
                    raw_move_section(s, in_section_name, output);
                }
            }
            shndx++;
        }

        add_got_symbol_if_needed(in, output);
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
