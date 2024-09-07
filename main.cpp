#include <algorithm>
#include <cassert>
#include <complex>
#include <cstring>
#include <iostream>
#include <elf.h>
#include <iomanip>
#include <map>
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
            code = 'D';
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

    pair<int, section*> sec_for(program& p, Elf32_Addr addr, int shndx = 0, bool top_addr_incl = false) {
        if (shndx > 0) {
            int idx = 0;
            for (auto s : p.sections) {
                if (idx == shndx && s->hdr->sh_addr <= addr && addr <= s->hdr->sh_addr + s->hdr->sh_size)
                    return {idx, s};
                idx++;
            }
        }

        int i = 0;
        for (auto s : p.sections) {
            if (s->hdr->sh_addr <= addr && addr < s->hdr->sh_addr + s->hdr->sh_size + top_addr_incl)
                return {i, s};
            i++;
        }
        return {0, nullptr};
    }

    optional<elf_symbol> sym_for(program const& in, program& out, int old_idx) {
        for (auto s : out.symtab->symbols)
            if (s.old_idx == old_idx)
                return s;

        Elf32_Sym old_s_idx = in.symtab->symbols[old_idx].symbol;
        for (auto s : out.symtab->symbols) {
            Elf32_Sym s_old = in.symtab->symbols[s.old_idx].symbol;
            int bind_s = ELF32_ST_BIND(s_old.st_info);
            int bind_old = ELF32_ST_BIND(old_s_idx.st_info);
            if (s_old.st_value == old_s_idx.st_value && bind_s == bind_old)
                return s;
        }

        for (auto s : out.symtab->symbols) {
            Elf32_Sym s_old = in.symtab->symbols[s.old_idx].symbol;
            if (s_old.st_value == old_s_idx.st_value)
                return s;
        }

        return {};
    }

    Elf32_Off got_symbol_off(program& in, Elf32_Sym symbol) {
        for (int i = 0; i < in.got->hdr->sh_size; i += 4) {
            Elf32_Addr* addr = (Elf32_Addr*)&in.got->data[i];
            if (*addr == symbol.st_value)
                return i;
        }
        log("No GOT entry for " + std::to_string(symbol.st_value));
        return symbol.st_value;
    }

    void fix_segment(program& in, program &out, Elf32_Rel in_rel, Elf32_Rel out_rel, elf_symbol& out_sym, section* outsec) {
        Elf32_Word* value = (Elf32_Word*) &outsec->data[out_rel.r_offset];
        // A - The addend used to compute the value of the relocatable field.
        int a = 0;
        // S - The value of the symbol whose index resides in the relocation entry.
        Elf32_Addr s = in.symtab->symbols[out_sym.old_idx].symbol.st_value;
        // P - The section offset or address of the storage unit being relocated, computed using r_offset.
        Elf32_Off p = in_rel.r_offset;
        // GOT - The address of the global offset table.
        Elf32_Off got = 0;
        // L - The section offset or address of the procedure linkage table entry for a symbol.
        Elf32_Off l = 0;

        if (in.got != nullptr) {
            got = in.got->hdr->sh_addr;
        }

        int type = ELF32_R_TYPE(in_rel.r_info);
        if (type == R_386_32) {
            // S + A
            a = *value - s;
        } else if (type == R_386_PC32) {
            a =  *value - s + p;
        } else if (type == R_386_GOTPC) {
            a = *value - got + p;
        } else if (type == R_386_GOTOFF) {
            a = *value - s + got;
        } else if (type == R_386_GOT32) {
            // G - The offset into the global offset table at which the address of the relocation entry's
            //  symbol resides during execution
            int g = got_symbol_off(in, in.symtab->symbols[out_sym.old_idx].symbol);
            a = *value - g;
        } else if (type == R_386_PLT32) {

        } else {
            log("Unsupported relo type: ", type);
        }

        *value = a;
    }

    void convert_rels(program& in, program& out) {
        auto all_reltabs = in.find_rels();
        for (auto reltab : all_reltabs) {
            for (auto rel : reltab->rels) {
                int r_sym = ELF32_R_SYM(rel.r_info);

                auto outsec = sec_for(out, rel.r_offset);
                auto outrel = rel_for(out, outsec.second);
                auto outsym = sym_for(in, out, r_sym);
                if (outsym.has_value() && outsym.value().old_idx == 0) {
                    log("Warning: rel for an empty symbol");
                } else if (!outsym.has_value()) {
                    log("Relocation for unknown symbol old_idx=", r_sym);
                    outsym = optional(elf_symbol{});
                }

                auto new_rel = Elf32_Rel{
                    .r_offset = rel.r_offset - outsec.second->hdr->sh_addr,
                    .r_info = ELF32_R_INFO(outsym->new_idx, ELF32_R_TYPE(rel.r_info)),
                };
                outrel->rels.push_back(new_rel);
                fix_segment(in, out, rel, new_rel, outsym.value(), outsec.second);
            }
        }
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

    vector<pair<string, elf_symbol>> remove_duplicates(vector<pair<string, elf_symbol>>& symbols) {
        map<string, vector<elf_symbol>> present;
        for (auto sp : symbols)
            present[sp.first].push_back(sp.second);

        vector<pair<string, elf_symbol>> no_duplicates;
        for (auto p : present) {
            // obj lub fun
            bool ok = false;
            for (auto sym: p.second)
                if (ELF32_ST_TYPE(sym.symbol.st_info) == STT_FUNC || ELF32_ST_TYPE(sym.symbol.st_info) == STT_OBJECT) {
                    no_duplicates.push_back({p.first, sym});
                    ok = true;
                    break;
                }

            // size
            if (!ok) {
                for (auto sym: p.second)
                    if (sym.symbol.st_size > 0) {
                        no_duplicates.push_back({p.first, sym});
                        ok = true;
                        break;
                    }
            }

            // randomowo
            if (!ok) {
                no_duplicates.push_back({p.first, *p.second.begin()});
            }
        }
        return no_duplicates;
    }

    void parse_file_and_mem(program& in, program& out, section *s, set<int>& nrs, int shndx) {
        vector<elf_symbol> ssyms = section_symbols_asc(in, shndx);
        vector<elf_symbol> all_syms = in.symbols_in_section_asc(shndx);
        string s_name = in.shstrtab->str_by_offset(s->hdr->sh_name);
        const Elf32_Addr max_s_addr = s->hdr->sh_size + s->hdr->sh_addr;

        vector<pair<string, elf_symbol>> section_symbols;
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
            while (all_syms_ptr < all_syms.size() && all_syms[all_syms_ptr].symbol.st_value == addr) {
                auto in_sym = all_syms[all_syms_ptr];
                string name = out_section_name(s_name, in_sym.symbol);
                auto sym = elf_symbol{
                    .symbol = in_sym.symbol,
                    .old_idx = in_sym.old_idx,
                    .new_idx = 0,
                };
                sym.symbol.st_shndx = shndx_current;
                sym.symbol.st_value -= current->hdr->sh_addr;
                assert(sym.symbol.st_value >= 0);
                section_symbols.push_back({name, sym});
                all_syms_ptr++;

                if (nrs.count(in_sym.old_idx) > 0)
                    nrs.erase(in_sym.old_idx);
                //else
                    //log("Warning: redundant symbol created");
            }

            // update pointers
            current->hdr->sh_size++;
            current->append(&s->data[i], 1);
        }

        auto no_dups = remove_duplicates(section_symbols);
        for (auto sym : no_dups)
            out.add_symbol(sym.first, sym.second);
    }

    void parse_mem(program& in, program& out, string s_name, section* s, int shndx) {
        auto outsec = out.add_section(s_name);
        int name = outsec->hdr->sh_name;
        *outsec->hdr = *s->hdr;
        outsec->hdr->sh_name = name;
        outsec->old_idx = shndx;
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

    void pick(vector<elf_symbol>& to, vector<elf_symbol>& outof, std::function<bool(elf_symbol)> filter) {
        vector<elf_symbol> matching;
        copy_if(outof.begin(), outof.end(), std::back_inserter(matching), filter);
        remove_if(outof.begin(), outof.end(), filter);

        for (auto x : matching) {
            bool contains = false;
            for (auto tx : to)
                if (tx == x)
                    contains = true;
            if (!contains)
                to.push_back(x);
        }
    }

    set<int> non_redundant_symbols(program& in) {
        auto reltabs = in.find_rels();
        auto all = in.symtab->symbols;
        vector<elf_symbol> picked;

        pick(picked, all, [](elf_symbol a) {
            return ELF32_ST_TYPE(a.symbol.st_info) == STT_FUNC || ELF32_ST_TYPE(a.symbol.st_info) == STT_OBJECT || ELF32_ST_BIND(a.symbol.st_info);
        });

        set<int> cand;
        for (auto rtab : reltabs)
            for (auto rel : rtab->rels)
                cand.insert(ELF32_R_SYM(rel.r_info));
        pick(picked, all, [&](elf_symbol a) {
            return cand.count(a.old_idx);
        });

        set<int> sym_idxes;
        for (auto sym : picked)
            sym_idxes.insert(sym.old_idx);
        return sym_idxes;
    }

    void add_start_symbol(program& in, program& out, set<int> nrs) {
        int sidx = 0;
        for (auto s : in.symtab->symbols) {
            if (in.strtab->str_by_offset(s.symbol.st_name) == "_start") {
                sidx = s.old_idx;
                break;
            }
        }

        for (auto sym : out.symtab->symbols)
            if (sidx == sym.old_idx) {
                log("_start found!");
                out.add_symbol("_start", sym);
                if (nrs.count(sidx) > 0)
                    nrs.erase(sidx);
            }
    }

    void add_rem_symbol(program& in, program& out, elf_symbol& sym) {
        string sname = in.strtab->str_by_offset(sym.symbol.st_name);
        if (sym.symbol.st_shndx == SHN_ABS || ELF32_ST_BIND(sym.symbol.st_info) == STB_WEAK) {
            out.add_symbol(sname, sym);
            return;
        }

        // For symbols at the beginning of a 0-sized section.
        std::pair<int, section*> insec1 = {sym.symbol.st_shndx, in.sections[sym.symbol.st_shndx]};
        auto insec2 = insec1;//sec_for(in, sym.symbol.st_value, sym.symbol.st_shndx, true);
        // For symbols exactly after the section.
        auto outsec1 = sec_for(out, sym.symbol.st_value, sym.symbol.st_shndx);
        auto outsec2 = sec_for(out, sym.symbol.st_value, sym.symbol.st_shndx, true);
        if ((insec1.second != nullptr || insec2.second != nullptr)
            && (outsec1.second != nullptr || outsec2.second != nullptr)) {
            auto insec = insec1.second == nullptr ? insec2 : insec1;
            auto outsec = outsec1.second == nullptr ? outsec2 : outsec1;
            assert(sym.symbol.st_value >= outsec.second->hdr->sh_addr);
            //string sec_name = in.shstrtab->str_by_offset(insec.second->hdr->sh_name);
            //string sname = out_section_name(sec_name, sym.symbol);
            string sname = in.strtab->str_by_offset(sym.symbol.st_name);
            // For sections of size 0, when changing the size, linker
            // also changes symbol addresses after the end
            // of the section. So, for .stack, this is needed
            if (outsec.second->hdr->sh_type == SHT_NOBITS)
                sym.symbol.st_value = 0;
            else
                sym.symbol.st_value -= outsec.second->hdr->sh_addr;
            sym.symbol.st_shndx = outsec.first;
            out.add_symbol(sname, sym);
        } else {
            log("Warning: Skipping symbol");
        }
    }

    void add_rem_symbols(program& in, program& out, set<int>& nrs) {
        for (int i : nrs)
            add_rem_symbol(in, out, in.symtab->symbols[i]);
    }

    void solve(program in, string out) {
        program output{};
        output.ehdr.e_machine = in.ehdr.e_machine;
        output.ehdr.e_version = in.ehdr.e_version;
        output.ehdr.e_entry = in.ehdr.e_entry;
        output.init();

        set<int> nrs = non_redundant_symbols(in);
        int shndx = 0;
        for (auto s : in.sections) {
            string in_section_name(&in.shstrtab->data[s->hdr->sh_name]);
            if (s->hdr->sh_type == SHT_PROGBITS) {
                if (in_section_name == ".got") {
                    // skip the section
                } else {
                    parse_file_and_mem(in, output, s, nrs, shndx);
                }
            } else if (s->hdr->sh_type == SHT_NOBITS) {
                parse_mem(in, output, in_section_name, s, shndx);
            }
            shndx++;
        }

        // add a dummy _start symbol, for the sake of e_entry
        add_start_symbol(in, output, nrs);

        add_rem_symbols(in, output, nrs);

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
