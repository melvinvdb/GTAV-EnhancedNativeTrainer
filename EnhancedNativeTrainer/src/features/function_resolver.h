#pragma once
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include "misc.h"
#include "..\debug\debuglog.h"

enum class FunctionID {
    RegisterFile
};

inline const char* ToString(FunctionID id) {
    switch (id) {
    case FunctionID::RegisterFile: return "RegisterFile";
    default:                       return "Unknown";
    }
}

template <FunctionID>
struct FunctionTraits;  // forward declaration

template <>
struct FunctionTraits<FunctionID::RegisterFile> {
    using type = uint32_t * (*)(int*, const char*, bool, const char*, bool);
};

namespace FunctionResolver::detail {
    struct PatternVariant {
        const char* bytes;
        const char* mask;
    };

    struct PatternDef {
        FunctionID func;
        bool did_search;
        intptr_t resolved_address;
        PatternVariant variants[4];
    };

    inline PatternDef g_Patterns[] = {
        {
            FunctionID::RegisterFile,
            false,
            0,
            {
                { "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x7C\x24\x00\x41\x54\x41\x56\x41\x57\x48\x83\xEC\x50\x48\x8B\xEA\x4C\x8B\xFA\x48\x8B\xD9\x4D\x85\xC9", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxx" }, // GTA V Legacy
                { "\x41\x57\x41\x56\x56\x57\x55\x53\x48\x83\xEC\x58\x4C\x89\xCF\x48\x89\xD6\x49\x89\xCE", "xxxxxxxxxxxxxxxxxxxxx" }, // GTA V Enhanced
                { nullptr, nullptr },
                { nullptr, nullptr },
            }
        }
    };
}

template <FunctionID ID>
typename FunctionTraits<ID>::type ResolveFunction()
{
    using namespace FunctionResolver::detail;
    intptr_t addr = 0;

    for (auto& entry : g_Patterns) {
        if (entry.func != ID) {
            continue;
        }

        if (entry.did_search) {
            return reinterpret_cast<typename FunctionTraits<ID>::type>(entry.resolved_address);
        }

        for (size_t i = 0; i < std::size(entry.variants); i++) {
            auto& variant = entry.variants[i];
            if (!variant.bytes) {
                break;
            }
            intptr_t found = FindPatternJACCO(variant.bytes, variant.mask);
            if (found) {
                write_text_to_log_file("Found address to function " + std::string(ToString(entry.func)) + " add index " + std::to_string(i));
                entry.did_search = true;
                entry.resolved_address = found;
                addr = found;
                break;
            }
        }

        if (!addr) {
            write_text_to_log_file("[ERROR] Failed finding address to function " + std::string(ToString(entry.func)));
            entry.did_search = true;
        }
    }

    return reinterpret_cast<typename FunctionTraits<ID>::type>(addr);
}