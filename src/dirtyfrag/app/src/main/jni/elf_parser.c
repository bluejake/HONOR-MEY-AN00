#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/elf.h>
#include "reporter.h"
#include "obf_strings.h"

int find_hook_target(const char *libcxx, const char *symname,
                     uint64_t *hook_target, uint64_t *payload_target,
                     uint32_t *first_instruction, struct Reporter *reporter) {
    *hook_target = 0;
    *payload_target = 0;

    int fd = open(libcxx, O_RDONLY);
    if (fd < 0) {
        REPORTLN(OBF(31), libcxx, strerror(errno));
        return 1;
    }

    Elf64_Ehdr hdr;
    if (read(fd, (char *)&hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
        REPORTLN(OBF(89), libcxx, strerror(errno));
        close(fd); return 1;
    }
    if (strncmp((char *)hdr.e_ident, obf_cat2(90,91), 4) != 0) {
        REPORTLN(OBF(92), libcxx);
        close(fd); return 1;
    }
    if (lseek64(fd, hdr.e_phoff, SEEK_SET) < 0) {
        REPORTLN(OBF(93), strerror(errno));
        close(fd); return 1;
    }
    if (hdr.e_phentsize != sizeof(Elf64_Phdr)) {
        REPORTLN(OBF(94), hdr.e_phentsize);
        close(fd); return 1;
    }

    uint64_t executable_off = 0;
    uint64_t executable_vaddr = 0;
    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (read(fd, (char *)&phdr, sizeof(phdr)) < 0) {
            REPORTLN(OBF(95), i, strerror(errno));
            close(fd); return 1;
        }
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            *payload_target = phdr.p_offset + phdr.p_filesz;
            executable_off   = phdr.p_offset;
            executable_vaddr = phdr.p_vaddr;
            break;
        }
    }

    if (lseek64(fd, hdr.e_shoff + hdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) < 0) {
        REPORTLN(OBF(96), strerror(errno));
        close(fd); return 1;
    }
    Elf64_Shdr str_shdr;
    if (read(fd, (char *)&str_shdr, sizeof(str_shdr)) < 0) {
        REPORTLN(OBF(97), strerror(errno));
        close(fd); return 1;
    }

    uint64_t dynstr = 0, dynsym_offset = 0, dynsym_size = 0;
    for (int i = 0; i < hdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        if (lseek64(fd, hdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) < 0) {
            REPORTLN(OBF(98), i, strerror(errno));
            close(fd); return 1;
        }
        if (read(fd, (char *)&shdr, sizeof(shdr)) < 0) {
            REPORTLN(OBF(99), i, strerror(errno));
            close(fd); return 1;
        }
        if (lseek64(fd, shdr.sh_name + str_shdr.sh_offset, SEEK_SET) < 0) {
            REPORTLN(OBF(100), i, strerror(errno));
            close(fd); return 1;
        }
        char name[100];
        if (read(fd, name, sizeof(name) - 1) < 0) {
            REPORTLN(OBF(101), i, strerror(errno));
            close(fd); return 1;
        }
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, OBF(102)) == 0) dynstr = shdr.sh_offset;
        if (strcmp(name, OBF(103)) == 0) { dynsym_offset = shdr.sh_offset; dynsym_size = shdr.sh_size; }
    }

    if (dynstr == 0 || dynsym_offset == 0) {
        REPORTLN(OBF(104), libcxx);
        close(fd); return 1;
    }

    for (int i = 0; i < (int)(dynsym_size / sizeof(Elf64_Sym)); i++) {
        Elf64_Sym sym;
        if (lseek64(fd, dynsym_offset + i * sizeof(Elf64_Sym), SEEK_SET) < 0) {
            REPORTLN(OBF(105), i, strerror(errno));
            close(fd); return 1;
        }
        if (read(fd, (char *)&sym, sizeof(sym)) < 0) {
            REPORTLN(OBF(106), i, strerror(errno));
            close(fd); return 1;
        }
        if (lseek64(fd, dynstr + sym.st_name, SEEK_SET) < 0) {
            REPORTLN(OBF(107), i, strerror(errno));
            close(fd); return 1;
        }
        char name[200];
        if (read(fd, name, sizeof(name) - 1) < 0) {
            REPORTLN(OBF(108), i, strerror(errno));
            close(fd); return 1;
        }
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, symname) == 0)
            *hook_target = sym.st_value - executable_vaddr + executable_off;
    }

    if (*hook_target == 0) {
        REPORTLN(OBF(109), symname, libcxx);
        close(fd); return 1;
    }

    if (lseek64(fd, *hook_target, SEEK_SET) < 0) {
        REPORTLN(OBF(110), strerror(errno));
        close(fd); return 1;
    }
    if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
        REPORTLN(OBF(111), strerror(errno));
        close(fd); return 1;
    }

    if (*first_instruction == 0xd503233fU || *first_instruction == 0xd503245f) {
        REPORTLN(OBF(112));
        *hook_target += 4UL;
        if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
            REPORTLN(OBF(113), strerror(errno));
            close(fd); return 1;
        }
    }

    close(fd);
    return 0;
}
