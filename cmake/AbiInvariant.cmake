# AbiInvariant.cmake - Enforce the ServiceRegistry cross-.so ABI precondition (R-12)
#
# ServiceRegistry hands a shared_ptr<IFoo> across the .so boundary and dispatches
# by std::type_index. type_index equality across .so boundaries — and a vtable
# laid out in a plugin .so being callable from libiora_core.so — REQUIRES that
# core and every interface-providing plugin are built with DEFAULT symbol
# visibility (no -fvisibility=hidden) and RTTI ENABLED (no -fno-rtti). If a
# consumer drifts to hidden visibility or disabled RTTI, ServiceRegistry::get<T>()
# silently returns nullptr (the capability appears absent — no crash, no error).
#
# This check fails CMake configuration if the forbidden flags appear in the
# global C++ flags or directory-level compile options. It is iora's side of the
# invariant. The same obligation binds EXTERNAL consumers (e.g.
# iora_web_middleware), which link installed iora at the install prefix and MUST
# be built with the same toolchain and inherit these flags — that enforcement
# lives in the consumer's own CMake and is out of this repository's scope.

function(iora_assert_abi_invariant)
    set(_flags "${CMAKE_CXX_FLAGS}")

    string(TOUPPER "${CMAKE_BUILD_TYPE}" _cfg)
    if(_cfg AND DEFINED CMAKE_CXX_FLAGS_${_cfg})
        set(_flags "${_flags} ${CMAKE_CXX_FLAGS_${_cfg}}")
    endif()

    get_directory_property(_dir_opts COMPILE_OPTIONS)
    set(_all "${_flags} ${_dir_opts}")

    if(_all MATCHES "-fvisibility=hidden")
        message(FATAL_ERROR
            "iora ABI invariant violated (R-12): -fvisibility=hidden breaks the "
            "cross-.so std::type_index equality ServiceRegistry depends on, which "
            "would make ServiceRegistry::get<T>() silently return nullptr. Remove "
            "-fvisibility=hidden from the iora build.")
    endif()

    if(_all MATCHES "-fno-rtti")
        message(FATAL_ERROR
            "iora ABI invariant violated (R-12): -fno-rtti breaks the cross-.so "
            "std::type_index equality ServiceRegistry depends on, which would make "
            "ServiceRegistry::get<T>() silently return nullptr. Remove -fno-rtti "
            "from the iora build.")
    endif()

    message(STATUS
        "iora ABI invariant OK (R-12): default visibility + RTTI for cross-.so "
        "ServiceRegistry dispatch")
endfunction()

# Per-target ABI check. The global check above only sees CMAKE_CXX_FLAGS and
# directory-level COMPILE_OPTIONS; it does NOT see -fvisibility=hidden / -fno-rtti
# added via target_compile_options() on an individual target. configure_iora_target
# calls this on every iora target it configures, closing the common per-target
# drift path. LIMITATION: this fires at configure time, so it catches flags
# present when the target is configured (the normal iora pattern adds them at
# target creation); flags appended to a target AFTER configure_iora_target, and
# flags on EXTERNAL consumer targets (e.g. iora_web_middleware), are out of reach
# — the external obligation is enforced in the consumer's own CMake (it links
# installed iora and must inherit the same toolchain/flags).
function(iora_assert_target_abi target_name)
    if(NOT TARGET ${target_name})
        return()
    endif()
    get_target_property(_topts ${target_name} COMPILE_OPTIONS)
    if(_topts)
        if(_topts MATCHES "-fvisibility=hidden")
            message(FATAL_ERROR
                "iora ABI invariant violated (R-12): target '${target_name}' sets "
                "-fvisibility=hidden via target_compile_options, breaking cross-.so "
                "std::type_index equality for ServiceRegistry. Remove it.")
        endif()
        if(_topts MATCHES "-fno-rtti")
            message(FATAL_ERROR
                "iora ABI invariant violated (R-12): target '${target_name}' sets "
                "-fno-rtti via target_compile_options, breaking cross-.so "
                "std::type_index equality for ServiceRegistry. Remove it.")
        endif()
    endif()
endfunction()
