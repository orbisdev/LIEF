#include <iostream>
#include <LIEF/LIEF.hpp>

// Sony SCE ELF specified types

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
    return 1;
  }
  LIEF::Logger::enable();
  LIEF::Logger::set_verbose_level(LIEF::LOGGING_LEVEL::LOG_INFO);

  std::unique_ptr<LIEF::Binary> binary = LIEF::Parser::parse(argv[1]);
  std::cout << *binary << std::endl;

}
