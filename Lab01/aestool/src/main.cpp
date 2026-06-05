#include "aestool.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
  try {
    return aestool::run(argc, argv);
  } catch (const std::exception& ex) {
    std::cerr << "ERROR: " << ex.what() << "\n";
    return 1;
  }
}

