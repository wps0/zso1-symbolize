#include "symbolize.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <functional>

namespace symbolize {
    section::section() {
        hdr = new Elf32_Shdr{};
    }

    void section::append(char const *mem, int len) {
        if (len == 0)
            return;
        char *ndata = new char[len + data_len];
        if (data_len > 0)
            memcpy(ndata, data, data_len);
        memcpy(ndata + data_len, mem, len);
        data_len += len;
        data = ndata;
    }

    bool elf_symbol::operator==(elf_symbol s) {
        // Linker-generated symbols are recognised by name
        if (linker_generated && s.linker_generated)
            return s.symbol.st_name == symbol.st_name;
        if (linker_generated || s.linker_generated)
            return false;
        return s.symbol.st_info == symbol.st_info && s.symbol.st_value == symbol.st_value
                && s.symbol.st_shndx == symbol.st_shndx;
    }

    sym_section::sym_section() {
        hdr = new Elf32_Shdr{
            .sh_name = 0,
            .sh_type = SHT_SYMTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_addralign = 0,
            .sh_entsize = sizeof(Elf32_Sym),
        };
    }

    rel_section::rel_section() {
        hdr->sh_type = SHT_REL;
        hdr->sh_flags |= SHF_INFO_LINK;
        hdr->sh_addralign = 4;
        hdr->sh_entsize = sizeof(Elf32_Rel);
    }

    str_section::str_section() {
        hdr = new Elf32_Shdr{
            .sh_name = 0,
            .sh_type = SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
        };
    }

    int str_section::offset(int n) {
        int off = 0;
        for (int i = 0; i < n; i++)
            off += entries[i].size() + 1;
        return off;
    }

    string str_section::str_by_offset(int off) {
        int coff = 0;
        for (const string& s : entries) {
            if (off == coff)
                return s;
            if (off == coff + s.size())
                return "";
            if (off > coff && off < coff + s.size()) {
                int skip = off - coff;
                return s.substr(skip, s.size() - skip);
            }
            coff += s.size() + 1;
        }
        assert(false);
    }

    int str_section::last_offset() {
        return offset(entries.size());
    }

    program::program() {
        ehdr = {
            .e_ident = {0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            .e_type = ET_REL,
            .e_machine = 0,
            .e_version = 0,
            .e_entry = 0,
            .e_phoff = 0,
            .e_shoff = 0,
            .e_flags = 0,
            .e_ehsize = sizeof(Elf32_Ehdr),
            .e_phentsize = 0,
            .e_phnum = 0,
            .e_shentsize = sizeof(Elf32_Shdr),
            .e_shnum = 0,
            .e_shstrndx = 0
        };
    }

    program::~program() {
        for (auto ptr : sections) {
            if (ptr->hdr->sh_type == SHT_REL)
                delete (rel_section*)ptr;
            else if (ptr->hdr->sh_type == SHT_SYMTAB)
                delete (sym_section*)ptr;
            else if (ptr->hdr->sh_type == SHT_STRTAB)
                delete (str_section*)ptr;
            else
                delete ptr;
        }
        for (auto ptr : phdrs)
            delete ptr;
        delete[] raw;
    }

    void program::init() {
        auto empty_sec = new section();
        auto empty_hdr = new Elf32_Shdr{};
        sections.push_back(empty_sec);
        shdrs.push_back(empty_hdr);
        empty_sec->hdr = empty_hdr;

        symtab = add_sym_section();
        symtab->symbols.push_back({});

        strtab = add_str_section();
        strtab->entries.push_back("");

        shstrtab = add_str_section();
        shstrtab->entries.push_back("");
        shstrtab->entries.push_back(".symtab");
        shstrtab->entries.push_back(".strtab");
        shstrtab->entries.push_back(".shstrtab");

        assert(shstrtab->entries[1] == ".symtab");
        symtab->hdr->sh_name = shstrtab->offset(1);
        assert(shstrtab->entries[2] == ".strtab");
        strtab->hdr->sh_name = shstrtab->offset(2);
        assert(shstrtab->entries[3] == ".shstrtab");
        shstrtab->hdr->sh_name = shstrtab->offset(3);
    }

    void program::load(string file) {
        FILE *f = fopen(file.c_str(), "rb");
        assert(f);

        raw_len = 0;
        raw = new char[64];
        int nbytes, raw_sz = 64;
        while ((nbytes = fread(raw + raw_len, 1, raw_sz - raw_len, f))) {
            raw_len += nbytes;

            if (raw_len == raw_sz) {
                raw_sz *= 2;
                char *raw2 = new char[raw_sz];
                memcpy(raw2, raw, raw_len);
                delete[] raw;
                raw = raw2;
            }
        }
        fclose(f);

        log("Read file of size ", raw_len);

        memcpy(&ehdr, raw, sizeof(ehdr));

        Elf32_Off off = ehdr.e_shoff;
        for (int i = 0; i < ehdr.e_shnum; i++) {
            auto shdr = new Elf32_Shdr{};
            memcpy(shdr, &raw[off], ehdr.e_shentsize);
            shdrs.push_back(shdr);
            off += ehdr.e_shentsize;
        }
        log("Read ", shdrs.size(), " section headers");

        off = ehdr.e_phoff;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            auto phdr = new Elf32_Phdr{};
            memcpy(phdr, &raw[off], ehdr.e_phentsize);
            phdrs.push_back(phdr);
            off += ehdr.e_phentsize;
        }
        log("Read ", phdrs.size(), " program headers");

        int idx = 0;
        for (auto hdr: shdrs) {
            section *s;
            if (hdr->sh_type == SHT_SYMTAB) {
                auto symtab = new sym_section();
                int upto = hdr->sh_offset + hdr->sh_size;
                int sym_idx = 0;
                for (int i = hdr->sh_offset; i < upto; i += hdr->sh_entsize) {
                    Elf32_Sym sym;
                    memcpy(&sym, &raw[i], hdr->sh_entsize);
                    symtab->symbols.push_back({.symbol = sym, .old_idx = sym_idx});
                    sym_idx++;
                }
                this->symtab = symtab;
                s = symtab;
            } else if (hdr->sh_type == SHT_REL) {
                auto reltab = new rel_section();
                int upto = hdr->sh_offset + hdr->sh_size;
                for (int i = hdr->sh_offset; i < upto; i += hdr->sh_entsize) {
                    Elf32_Rel rel;
                    memcpy(&rel, &raw[i], hdr->sh_entsize);
                    reltab->rels.emplace_back(elf_rel{.rel = rel, .old_sym = ELF32_R_SYM(rel.r_info)});
                }
                s = reltab;
            } else if (idx == this->ehdr.e_shstrndx) {
                assert(hdr->sh_type == SHT_STRTAB);
                this->shstrtab = load_strtab(*hdr);
                s = this->shstrtab;
            } else if (hdr->sh_type == SHT_STRTAB) {
                this->strtab = load_strtab(*hdr);
                s = this->strtab;
            } else {
                s = new section();
            }

            s->data = raw + hdr->sh_offset;
            s->hdr = hdr;
            sections.push_back(s);
            idx++;
        }

        // set GOT
        for (auto s : sections)
            if (shstrtab->str_by_offset(s->hdr->sh_name) == ".got")
                got = s;

        // mark linker-generated symbols
        for (auto& s : symtab->symbols) {
            string sname = strtab->str_by_offset(s.symbol.st_name);
            s.linker_generated = linker_generated_symbols.count(sname);
        }
    }

    void buf_add(char **buf, int &buf_sz, void *data, int len) {
        assert(len >= 0);
        if (len <= 0)
            return;
        char *nbuf = new char[buf_sz + len];
        if (buf_sz > 0) {
            memcpy(nbuf, *buf, buf_sz);
            delete[] *buf;
        }
        memcpy(nbuf + buf_sz, data, len);
        buf_sz += len;
        *buf = nbuf;
    }

    void program::save(string file) {
        raw = nullptr;
        raw_len = 0;

        int symtab_nr = -1, shstrtab_nr = -1, strtab_nr = -1;
        for (int i = 0; i < sections.size(); i++) {
            auto s = sections[i];
            if (s == symtab)
                symtab_nr = i;
            else if (s == strtab)
                strtab_nr = i;
            else if (s == shstrtab)
                shstrtab_nr = i;
        }

        assert(sections.size() == shdrs.size());

        ehdr.e_shoff = sizeof(Elf32_Ehdr);
        ehdr.e_shnum = shdrs.size();
        ehdr.e_shstrndx = shstrtab_nr;

        buf_add(&raw, raw_len, &ehdr, sizeof(ehdr));

        for (auto shdr: shdrs) {
            buf_add(&raw, raw_len, shdr, sizeof(*shdr));
        }

        int idx = 0;
        for (auto s: sections) {
            // Has to be this way to reflect changes after writing to raw.
            auto shdr = [this, idx] { return (Elf32_Shdr *) &this->raw[ehdr.e_shoff + idx * ehdr.e_shentsize]; };
            string s_name = shstrtab->str_by_offset(shdr()->sh_name);

            // Stack is initialized by picolib.ld, but the section
            // is needed for associating symbols with sections.
            if (s_name == ".stack")
                shdr()->sh_size = 0;

            int align = max((Elf32_Word) 1, s->hdr->sh_addralign);
            int pad_len = raw_len % align;
            char pad[pad_len]{};
            buf_add(&raw, raw_len, &pad, pad_len);

            // Fix undefined header values
            shdr()->sh_offset = raw_len;
            //shdr()->sh_addr = 0;

            str_section *strtab;
            rel_section *reltab;

            switch (shdr()->sh_type) {
                case SHT_REL:
                    shdr()->sh_link = symtab_nr;
                    reltab = (rel_section*) s;
                    for (auto rel: reltab->rels)
                        buf_add(&raw, raw_len, &rel.rel, sizeof(Elf32_Rel));
                    break;

                case SHT_SYMTAB:
                    save_symtab(shdr, strtab_nr, (sym_section*)s);
                    break;

                case SHT_STRTAB:
                    strtab = static_cast<str_section *>(s);
                    for (auto const &s: strtab->entries)
                        buf_add(&raw, raw_len, (void *) s.c_str(), s.size() + 1);
                    break;

                default:
                    shdr()->sh_link = 0;
                    shdr()->sh_info = 0;
                    break;
            }

            buf_add(&raw, raw_len, s->data, s->data_len);
            if (shdr()->sh_type == SHT_NULL || shdr()->sh_type == SHT_NOBITS) {
                shdr()->sh_offset = 0;
            } else {
                shdr()->sh_size = raw_len - shdr()->sh_offset;
            }
            idx++;
        }

        // e_entry
        FILE *f = fopen(file.c_str(), "wb");
        int nwrote = 0;
        do {
            int ret = fwrite(raw + nwrote, 1, raw_len - nwrote, f);
            assert(ret);
            nwrote += ret;
        } while (nwrote < raw_len);
        fclose(f);
    }

    section *program::add_section(string name) {
        auto sptr = new section();
        add_section(sptr);
        sptr->hdr->sh_name = shstrtab->offset(shstrtab->entries.size());
        shstrtab->entries.push_back(name);
        return sptr;
    }

    void program::add_section(section *sptr) {
        sections.push_back(sptr);
        shdrs.push_back(sptr->hdr);
    }

    void program::sort_symtabs() {
        for (auto s: sections) {
            if (s->hdr->sh_type != SHT_SYMTAB)
                continue;

            sym_section *symtab = (sym_section*)s;
            sort(symtab->symbols.begin(), symtab->symbols.end(), SYMTAB_CMP);
            // Now fix symbol positions
            for (int i = 0; i < symtab->symbols.size(); i++)
                symtab->symbols[i].new_idx = i;
        }
    }

    void program::save_symtab(function<Elf32_Shdr*(void)> shdr, int strtab_nr, sym_section *symtab) {
        shdr()->sh_link = strtab_nr;

        // One greater than the symbol table index of the last local symbol,STB_LOCAL
        while (shdr()->sh_info < symtab->symbols.size()
               && ELF32_ST_BIND(symtab->symbols[shdr()->sh_info].symbol.st_info) == STB_LOCAL)
            shdr()->sh_info++;

        for (auto sym: symtab->symbols) {
            buf_add(&raw, raw_len, &sym.symbol, sizeof(sym.symbol));
        }
    }

    str_section *program::add_str_section() {
        auto sptr = new str_section();
        add_section(sptr);
        return sptr;
    }

    sym_section *program::add_sym_section() {
        auto sptr = new sym_section();
        add_section(sptr);
        return sptr;
    }

    rel_section * program::add_rel_section(string name, int sh_link) {
        auto sptr = new rel_section();
        add_section(sptr);
        sptr->hdr->sh_info = sh_link;
        sptr->hdr->sh_name = shstrtab->last_offset();
        shstrtab->entries.push_back(name);
        return sptr;
    }

    int program::index_of(section *s) {
        for (int i = 0; i < sections.size(); i++)
            if (sections[i] == s)
                return i;
        return -1;
    }

    vector<rel_section *> program::find_rels() {
        vector<rel_section*> rels;
        for (auto s : sections)
            if (s->hdr->sh_type == SHT_REL)
                rels.push_back((rel_section*) s);
        return rels;
    }

    void program::add_symbol(string name, elf_symbol& sym) {
        int name_off = strtab->last_offset();
        sym.symbol.st_name = name_off;
        sym.new_idx = symtab->symbols.size();
        strtab->entries.push_back(name);
        symtab->symbols.push_back(sym);
    }

    vector<elf_symbol> program::symbols_in_section_asc(int shndx) {
        vector<elf_symbol> syms;
        for (auto s : symtab->symbols)
            if (s.symbol.st_shndx == shndx)
                syms.push_back(s);
        sort(syms.begin(), syms.end(), SYMBOLS_ASC_BY_ADDR_CMP);
        return syms;
    }


    str_section *program::load_strtab(Elf32_Shdr shdr) {
        auto strtab = new str_section();
        int upto = shdr.sh_offset + shdr.sh_size;
        for (int i = shdr.sh_offset; i < upto; i++) {
            string name(raw + i);
            i += name.size();
            strtab->entries.push_back(name);
        }
        return strtab;
    }

}
