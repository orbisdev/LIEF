#include <iostream>
#include <string>
#include <LIEF/LIEF.hpp>

// Sony SCE ELF specified types

using namespace LIEF::ELF;

std::string encode_nid(uint64_t nVal, uint16_t library_id, uint16_t module_id)
{
  const char pCodes[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
  char encoded[16] = {0};
  encoded[0] = pCodes[nVal >> 58];
  encoded[1] = pCodes[(nVal >> 52) & 0x3F];
  encoded[2] = pCodes[(nVal >> 46) & 0x3F];
  encoded[3] = pCodes[(nVal >> 40) & 0x3F];
  encoded[4] = pCodes[(nVal >> 34) & 0x3F];
  encoded[5] = pCodes[(nVal >> 28) & 0x3F];
  encoded[6] = pCodes[(nVal >> 22) & 0x3F];
  encoded[7] = pCodes[(nVal >> 16) & 0x3F];
  encoded[8] = pCodes[(nVal >> 10) & 0x3F];
  encoded[9] = pCodes[(nVal >> 4) & 0x3F];
  encoded[10] = pCodes[4 * (nVal & 0xF)];
  encoded[11] = '#';
  encoded[12] = pCodes[4 * (library_id & 0xF)];
  encoded[13] = '#';
  encoded[14] = pCodes[4 * (module_id & 0xF)];
  encoded[15] = '\0';

  return std::string(encoded);
}

int main(int argc, char **argv)
{
  if (argc != 3)
  {
    std::cerr << "Usage: " << argv[0] << " <binary> <binary>" << std::endl;
    return 1;
  }
  LIEF::Logger::enable();
  LIEF::Logger::set_verbose_level(LIEF::LOGGING_LEVEL::LOG_INFO);

  std::unique_ptr<LIEF::ELF::Binary> binary = LIEF::ELF::Parser::parse(argv[1]);

  switch (binary->header().file_type())
  {
  case E_TYPE::ET_EXEC:
  {
    binary->header().file_type(LIEF::ELF::E_TYPE::ET_EXEC);
    break;
  }
  case E_TYPE::ET_DYN:
  {
    binary->header().file_type(LIEF::ELF::E_TYPE::ET_SCE_DYNAMIC);
    break;
  }
  }
  // set module name to elf output name
  char *fs = strrchr(argv[1], '/');
  char *bs = strrchr(argv[1], '\\');
  char *base = argv[1];

  if (fs && bs)
  {
    base = (fs > bs) ? (fs) : (bs);
  }
  else if (fs)
  {
    base = fs + 1;
  }
  else if (bs)
  {
    base = bs + 1;
  }

  uint16_t version_major = 1;
  uint16_t version_minor = 1;

  std::string elf_name(base);

  elf_name = elf_name.substr(0, elf_name.find("."));

  DynamicEntryLibrary sce_module_info_entry = {};
  sce_module_info_entry.tag(DYNAMIC_TAGS::DT_SCE_MODULE_INFO);
  sce_module_info_entry.name(elf_name);
  sce_module_info_entry.value((version_major * 0x1000000000000) | (version_minor * 0x10000000000));

  binary->add(sce_module_info_entry);

  DynamicEntry sce_module_attr_entry = {};
  sce_module_attr_entry.tag(DYNAMIC_TAGS::DT_SCE_MODULE_ATTR);
  sce_module_attr_entry.value(0);

  binary->add(sce_module_attr_entry);

  uint16_t module_id = 0;
  uint16_t library_id = 0;

  for (auto &section : binary->sections())
  {

    if (section.type() == ELF_SECTION_TYPES::SHT_PROGBITS && (section.name().find(".orbis") != section.name().npos))
    {
      module_id++;
      library_id++;

      std::cout << section.name() << std::endl;

      std::string stripped = section.name().substr(14, section.name().length() - 14);

      std::string module_name = stripped.substr(0, stripped.find("."));

      stripped = stripped.substr(stripped.find(".") + 1);

      int module_major = std::atoi(&stripped.at(0));

      int module_minor = std::atoi(&stripped.at(2));

      std::cout << module_id << " module_name: " << module_name << " " << module_major << "." << module_minor << std::endl;

      stripped = stripped.substr(4);

      DynamicEntryLibrary needed_entry = {};
      needed_entry.tag(DYNAMIC_TAGS::DT_NEEDED);
      needed_entry.name(module_name + ".sprx");

      binary->add(needed_entry);

      DynamicEntryLibrary sce_needed_entry = {};
      sce_needed_entry.tag(DYNAMIC_TAGS::DT_SCE_NEEDED_MODULE);
      sce_needed_entry.name(module_name);
      sce_needed_entry.value((module_id * 0x1000000000000) | (module_major * 0x10000000000) | (module_minor * 0x100000000));
      binary->add(sce_needed_entry);

      std::string library_name = stripped.substr(0, stripped.find("."));

      stripped = stripped.substr(stripped.find(".") + 1);

      int library_major = std::atoi(&stripped.at(0));

      std::cout << library_id << " library_name: " << library_name << " " << library_major << std::endl;

      DynamicEntryLibrary sce_import_entry = {};
      sce_import_entry.tag(DYNAMIC_TAGS::DT_SCE_IMPORT_LIB);
      sce_import_entry.name(library_name);
      sce_import_entry.value((library_id * 0x1000000000000) | (library_major * 0x100000000));
      binary->add(sce_import_entry);

      DynamicEntry sce_import_attr_entry = {};
      sce_import_attr_entry.tag(DYNAMIC_TAGS::DT_SCE_IMPORT_LIB_ATTR);
      sce_import_attr_entry.value((library_id * 0x1000000000000) | 9);

      binary->add(sce_import_attr_entry);

      for (auto &symbol : binary->static_symbols())
      {
        if (!symbol.name().empty() && symbol.value() >= section.virtual_address() && symbol.value() <= section.virtual_address() + section.size())
        {
          uint64_t nid = *(uint64_t *)binary->get_content_from_virtual_address(symbol.value(), sizeof(uint64_t)).data();
          std::cout << symbol.name() << ":" << nid << std::endl;
          auto old_name = symbol.name();
          symbol.name(encode_nid(nid, library_id, module_id));
          auto dynamic_symbol = binary->add_dynamic_symbol(symbol);
          symbol.name(old_name);
        }
      }

      binary->remove_section(section.name());
    }
  }

  for (auto &relocation : binary->dynamic_relocations())
  {
    uint64_t target = 0;
    switch (static_cast<RELOC_x86_64>(relocation.type()))
    {
    case RELOC_x86_64::R_X86_64_RELATIVE:
      target = binary->section_from_virtual_address(relocation.symbol().value()).virtual_address() + relocation.addend();
      break;

    default:
      break;
    }

    for (auto &symbol : binary->dynamic_symbols())
    {
      if (!symbol.name().empty() && symbol.value() == target)
      {
        relocation.symbol(&symbol);
      }
    }
  }

  for (auto dynamic : binary->dynamic_entries())
  {
    switch (dynamic.tag())
    {
    case DYNAMIC_TAGS::DT_STRTAB:
    {
      DynamicEntry entry(dynamic);
      entry.tag(DYNAMIC_TAGS::DT_SCE_STRTAB);
      binary->add(entry);
      break;
    }
    case DYNAMIC_TAGS::DT_STRSZ:
    {
      DynamicEntry entry(dynamic);
      entry.tag(DYNAMIC_TAGS::DT_SCE_STRSZ);
      binary->add(entry);
      break;
    }

    case DYNAMIC_TAGS::DT_SYMTAB:
    {
      DynamicEntry entry(dynamic);
      entry.tag(DYNAMIC_TAGS::DT_SCE_SYMTAB);
      binary->add(entry);
      break;
    }

    case DYNAMIC_TAGS::DT_SYMENT:
    {
      DynamicEntry entry(dynamic);
      entry.tag(DYNAMIC_TAGS::DT_SCE_SYMENT);
      binary->add(entry);
      break;
    }

    default:
      break;
    }
  }


  binary->write(argv[2]);
  
  std::cout << *binary << std::endl;

}
