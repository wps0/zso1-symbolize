#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <elf.h>
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

    section* sec_for(program& p, Elf32_Rel rel) {
        for (auto s : p.sections)
            // TODO: rozmiary relokacji
            if (s->hdr->sh_addr >= rel.r_offset && rel.r_offset + 4 <= s->hdr->sh_addr + s->hdr->sh_size)
                return s;
        return nullptr;
    }

    void convert_rel(program const& in, program& out) {
        for (int i = 0; i < in.sections.size(); i++) {
            auto s = in.sections[i];
            if (s->hdr->sh_type != SHT_REL)
                continue;

            rel_section* reltab = (rel_section*)s;
            for (auto rel : reltab->rels) {
                auto sec = sec_for(out, rel);
                auto outrel = rel_for(out, sec);



                outrel->rels.push_back(Elf32_Rel{
                    .r_offset = rel.r_offset - sec->hdr->sh_addr,
                    .r_info = rel.r_info // TODO!
                });
            }
        }
    }

    void solve(program in, string out) {
        program output{};
        output.ehdr.e_machine = in.ehdr.e_machine;
        output.ehdr.e_version = in.ehdr.e_version;
        output.init();

/*        vector<Elf32_Sym*> working_sym;
        for (auto s : in.symtab) {
            Elf32_Sym* sym = new Elf32_Sym();
            memcpy(sym, s, sizeof(Elf32_Sym));
            working_sym.push_back(sym);
        }*/

        int shndx = 0;
        for (auto s : in.sections) {
            // sh_align - tylko dla pierwszej sekcji w rozbijanej grupie
            // sh_entsize - dla specyficzny
            string in_section_name(&in.shstrtab->data[s->hdr->sh_name]);
            if (s->hdr->sh_type == SHT_PROGBITS || s->hdr->sh_type == SHT_NOBITS) {
                auto syms = program::symbols_in_section_asc(s, in.symtab->symbols, shndx);
                bool is_first = true;
                for (auto sym : syms) {
                    // symbol new name
                    //string name = sym_name(s, &sym);
                    string name(&in.strtab->data[sym.symbol.st_name]);
                    Elf32_Word name_off = output.strtab->last_offset();
                    output.strtab->entries.push_back(name);

                    Elf32_Section sec_id = output.sections.size();
                    string sec_name = in_section_name + "." + name;
                    auto sec = output.add_section(sec_name);

                    sec->hdr->sh_type = s->hdr->sh_type;
                    sec->hdr->sh_flags = s->hdr->sh_flags;
                    sec->hdr->sh_size = sym.symbol.st_size;
                    sec->hdr->sh_addr = s->hdr->sh_addr;
                    if (is_first) {
                        sec->hdr->sh_addralign = s->hdr->sh_addralign;
                        is_first = false;
                    }
                    sec->append(s->data, sec->hdr->sh_size);

                    Elf32_Sym rel_sym{
                        .st_name = name_off,
                        .st_value = sym.symbol.st_value,
                        .st_size = sym.symbol.st_size,
                        .st_info = sym.symbol.st_info,
                        .st_other = sym.symbol.st_other,
                        .st_shndx = sec_id,
                    };
                    int sidx = output.symtab->symbols.size();
                    output.symtab->symbols.push_back(elf_symbol{
                        .symbol = rel_sym,
                        .old_idx = sym.old_idx,
                        .new_idx = sidx
                    });
                }
            }
            shndx++;
        }

        convert_rel(in, output);

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
