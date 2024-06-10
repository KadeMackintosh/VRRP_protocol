# CMakeList.txt : CMake project for vrrp, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()


project ("vrrp")

# Add source to this project's executable.
add_executable (vrrp main.c vrrp.c )
find_library(PCAP_LIBRARY pcap)
target_link_libraries(vrrp ${PCAP_LIBRARY})
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET vrrp PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
