#ifndef SYMBOLIZE_H
#define SYMBOLIZE_H
#include <elf.h>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace symbolize {
    using namespace std;

    class section {
    public:
        Elf32_Shdr* hdr;
        char* data = nullptr;
        int data_len = 0;

        section();

        void append(char const *mem, int len);
    };

    struct elf_symbol {
        Elf32_Sym symbol;
        int old_idx;
        int new_idx;
    };

    class sym_section : public section {
    public:
        sym_section();
        vector<elf_symbol> symbols;
        int got_off_idx;
    };

    class rel_section : public section {
    public:
        rel_section();
        vector<Elf32_Rel> rels;
    };

    // strtab - jak dziala ten offset?
    class str_section : public section {
    public:
        str_section();
        vector<string> entries;
        int offset(int i);
        string str_by_offset(int off);
        int last_offset();
    };

    class program {
    public:
        program();

        Elf32_Ehdr ehdr{};
        vector<section*> sections;
        vector<Elf32_Shdr*> shdrs;
        vector<Elf32_Phdr*> phdrs;
        sym_section *symtab;
        section *got = nullptr;
        str_section *strtab;
        str_section *shstrtab = nullptr;

        char* raw{};
        int raw_len{};

        void init();
        void load(string file);
        void save(string file);

        section* add_section(string name);
        str_section* add_str_section();
        sym_section* add_sym_section();
        rel_section* add_rel_section(string name_suffix, int sh_link);
        int index_of(section* s);
        vector<rel_section*> find_rels();

        void add_symbol(string name, elf_symbol &sym);

        vector<elf_symbol> symbols_in_section_asc(int shndx);
        static vector<elf_symbol> symbols_in_section_asc(section *s, vector<elf_symbol> section_syms, int shndx);
        void sort_symtabs();

    private:
        str_section* load_strtab(Elf32_Shdr shdr);
        void add_section(section*);

        void save_symtab(function<Elf32_Shdr *()> shdr, int strtab_nr, sym_section *symtab);
    };

    template<typename... T>
    void log_err(T... msg) {
        (std::cerr << ... << msg);
        std::cerr << std::endl;
    }

    template<typename... T>
    void log(T... msg) {
        std::cout << "log: ";
        (std::cout << ... << msg);
        std::cout << std::endl;
    }

    auto const SYMTAB_CMP = [](elf_symbol a, elf_symbol b) {
        if (ELF32_ST_BIND(a.symbol.st_info) == ELF32_ST_BIND(b.symbol.st_info)) {
            if (a.symbol.st_shndx == b.symbol.st_shndx)
                return a.symbol.st_value < b.symbol.st_value;
            return a.symbol.st_shndx < b.symbol.st_shndx;
        }
        return ELF32_ST_BIND(a.symbol.st_info) < ELF32_ST_BIND(b.symbol.st_info);
    };

    auto const SYMBOLS_ASC_BY_ADDR_CMP = [](elf_symbol a, elf_symbol b) {
        if (a.symbol.st_value != b.symbol.st_value)
            return a.symbol.st_value < b.symbol.st_value;
        int a_type = ELF32_ST_TYPE(a.symbol.st_info);
        int b_type = ELF32_ST_TYPE(a.symbol.st_info);
        if ((a_type == STT_FUNC || a_type == STT_OBJECT)
            && (b_type == STT_FUNC || b_type == STT_OBJECT))
            return ELF32_ST_BIND(a.symbol.st_info) < ELF32_ST_BIND(b.symbol.st_info);
        if (a_type == STT_FUNC || a_type == STT_OBJECT)
            return true;
        if (b_type == STT_FUNC || b_type == STT_OBJECT)
            return false;
        return ELF32_ST_BIND(a.symbol.st_info) < ELF32_ST_BIND(b.symbol.st_info);
    };

    auto const IS_A_BETTER_THAN_B = [](elf_symbol a, elf_symbol b) {
        int a_type = ELF32_ST_TYPE(a.symbol.st_info);
        int b_type = ELF32_ST_TYPE(a.symbol.st_info);
        if (a.symbol.st_size == b.symbol.st_size) {
            if (a_type == b_type)
                return ELF32_ST_BIND(a.symbol.st_info) < ELF32_ST_BIND(b.symbol.st_info);
            return a_type == STT_FUNC || a_type == STT_OBJECT;
        }
        return a.symbol.st_size > b.symbol.st_size;
    };
}

#endif //SYMBOLIZE_H
