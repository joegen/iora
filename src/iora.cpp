// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include <iora/iora.hpp>

int main(int argc, char** argv)
{
  try 
  {
    // Initialize the IoraService with command-line arguments
    iora::IoraService& svc = iora::IoraService::init(argc, argv);

    std::signal(SIGINT, 
      [](int) 
      {
        iora::IoraService::instance().terminate();
      }
    );
    
    svc.waitForTermination();
  }
  catch (const std::exception& ex)
  {
    std::cerr << "Error initializing IoraService: " << ex.what() << std::endl;
    iora::IoraService::shutdown();
    return EXIT_FAILURE;
  }
  
  iora::IoraService::shutdown();
  return 0;
}