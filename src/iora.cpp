#include <iora/iora.hpp>

int main(int argc, char** argv)
{
  iora::IoraService& svc = iora::IoraService::init(argc, argv);

  std::signal(SIGINT, 
    [](int) 
    {
      iora::IoraService::instance().terminate();
    }
  );
  
  svc.waitForTermination();
  iora::IoraService::shutdown();
  return 0;
}