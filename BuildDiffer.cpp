#include "pch.h"

#pragma managed(push, off)
#include <Windows.h>
#include <msdelta.h>
#include <memory>

#define BIT(x) (1 << x)
#define BIT64(x) (1ull << x)

// Supported executable types.
enum {
    EXECUTABLE_UNKNOWN,
    EXECUTABLE_NE,
    EXECUTABLE_LE,
    EXECUTABLE_LX,
    EXECUTABLE_PE,
};

enum {
    COMPARE_SECTION_BITS = 64 - 4
};

// Executable comparison result.
enum : UINT64 {
    COMPARE_IGNORE = 0, ///< Files have the same content, or are for different systems.
    COMPARE_DIFF_CODE = BIT(0), ///< Code is different.
    COMPARE_DIFF_RDATA = BIT(1), ///< Read-only data is different.
    COMPARE_DIFF_DATA = BIT(2), ///< Read-write data is different.
    COMPARE_DIFF_SECTIONS = BIT(3), ///< Section count or flags are different.
};


typedef struct _NE_SECTION_HEADER {
    WORD DataSector;
    WORD DataLength;
    WORD Flags;
    WORD AllocationSize;
} NE_SECTION_HEADER, * PNE_SECTION_HEADER;

// NE segment flags
enum {
    NE_SEGMENT_IS_DATA = BIT(0), // if set: data; if unset: code
    NE_SEGMENT_ALLOCATED = BIT(1),
    NE_SEGMENT_LOADED = BIT(2),
    NE_SEGMENT_TYPE_MASK = BIT(0) | BIT(1) | BIT(2),
    NE_SEGMENT_ITERATED = BIT(3),
    NE_SEGMENT_MOVEABLE = BIT(4),
    NE_SEGMENT_PURE = BIT(5),
    NE_SEGMENT_PRELOAD = BIT(6),
    NE_SEGMENT_READ_EXEC_ONLY = BIT(7),
    NE_SEGMENT_RELOCATABLE = BIT(8),
    NE_SEGMENT_HAS_SYMBOLS = BIT(9),
    NE_SEGMENT_RING_MASK = BIT(10) | BIT(11),
    NE_SEGMENT_DISCARDABLE = BIT(12)
};

typedef struct _LE_SECTION_HEADER {
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD Flags;
    DWORD PageTableIndex;
    DWORD PageTableCount;
    DWORD Reserved;
} LE_SECTION_HEADER, * PLE_SECTION_HEADER;

enum {
    IMAGE_LX_SIGNATURE = 0x584C,
};

// Incomplete LE CPU types.
enum {
    LE_CPU_286 = 1
};

// LE section flags
enum {
    LE_SECTION_MEM_READ = BIT(0),
    LE_SECTION_MEM_WRITE = BIT(1),
    LE_SECTION_MEM_EXEC = BIT(2),

    LE_SECTION_RESOURCE = BIT(3),
    LE_SECTION_DISCARDABLE = BIT(4),
    LE_SECTION_SHARED = BIT(5),
    LE_SECTION_PRELOAD = BIT(6),
    LE_SECTION_INVALID = BIT(7),
    LE_SECTION_SWAPPABLE = BIT(8),
    LE_SECTION_RESIDENT = BIT(9),
    LE_SECTION_DYNAMIC = BIT(10),
    LE_SECTION_RESERVED = BIT(11),
    LE_SECTION_ALIAS16 = BIT(12),
    LE_SECTION_BIGDEF = BIT(13),
    LE_SECTION_CONFORMING = BIT(14),
    LE_SECTION_PRIVILEGED = BIT(15)
};

// Gets the image base from a PE file.
template <typename TNtHeaders> static ULONGLONG GetImageBase(PIMAGE_NT_HEADERS pPe) {
    return ((TNtHeaders*)pPe)->OptionalHeader.ImageBase;
}

// Gets a data directory from a PE file.
template <typename TNtHeaders> static PIMAGE_DATA_DIRECTORY GetDataDirectory(PIMAGE_NT_HEADERS pPe, size_t DirectoryEntry) {
    if (((TNtHeaders*)pPe)->OptionalHeader.NumberOfRvaAndSizes < DirectoryEntry) return nullptr;
    return &((TNtHeaders*)pPe)->OptionalHeader.DataDirectory[DirectoryEntry];
}


// Determines if a directory entry is not present (null).
static bool DirectoryIsNull(PIMAGE_DATA_DIRECTORY Directory) {
    return Directory == nullptr || (Directory->VirtualAddress == 0 && Directory->Size == 0);
}

// Determines if a directory entry is within a section.
static bool DirectoryInSection(PIMAGE_SECTION_HEADER Section, PIMAGE_DATA_DIRECTORY Directory) {
    // A null directory cannot be within a section.
    if (DirectoryIsNull(Directory)) return false;

    if ((Section->VirtualAddress >= Directory->VirtualAddress) && (Section->VirtualAddress < Directory->VirtualAddress + Directory->Size))
        return true;

    if ((Directory->VirtualAddress >= Section->VirtualAddress) && (Directory->VirtualAddress < Section->VirtualAddress + Section->Misc.VirtualSize))
        return true;

    return false;
}

// Determines if a debug directory entry is within a section.
static bool DirectoryInSection(PIMAGE_SECTION_HEADER Section, PIMAGE_DEBUG_DIRECTORY Directory) {
    if (Directory->AddressOfRawData == 0) {
        if (Directory->PointerToRawData == 0) return false;
        if ((Section->PointerToRawData >= Directory->PointerToRawData) && (Section->PointerToRawData < Directory->PointerToRawData + Directory->SizeOfData))
            return true;

        if ((Directory->PointerToRawData >= Section->PointerToRawData) && (Directory->PointerToRawData < Section->PointerToRawData + Section->Misc.VirtualSize))
            return true;

        return false;
    }
    else {

        if ((Section->VirtualAddress >= Directory->AddressOfRawData) && (Section->VirtualAddress < Directory->AddressOfRawData + Directory->SizeOfData))
            return true;

        if ((Directory->AddressOfRawData >= Section->VirtualAddress) && (Directory->AddressOfRawData < Section->VirtualAddress + Section->Misc.VirtualSize))
            return true;

        return false;
    }
}

// Determines if an RVA is within a section, using a specified length.
template <typename TRva> static bool RvaInSection(PIMAGE_SECTION_HEADER Section, TRva rva, SIZE_T length) {
    if ((Section->VirtualAddress >= rva) && (Section->VirtualAddress < rva + length))
        return true;

    if ((rva >= Section->VirtualAddress) && (rva < Section->VirtualAddress + Section->Misc.VirtualSize))
        return true;

    return false;
}

// Determines if an RVA is within a section.
template <typename TRva> static bool TableRvaInSection(PIMAGE_SECTION_HEADER Section, TRva rva) {
    return RvaInSection(Section, rva, sizeof(TRva));
}

// Zeros out all possible IAT entries.
template <typename TRva> static void ClearIAT(const byte* base, const PIMAGE_SECTION_HEADER Section, PIMAGE_IMPORT_DESCRIPTOR Descriptor, bool IsBound) {
    // Zero out the TimeDateStamp, it might have a DLL timestamp of the imported DLL in it
    if (IsBound) Descriptor->TimeDateStamp = 0;
    // Get the rvaNames and rvaAddrs.
    auto rvarvaNames = Descriptor->OriginalFirstThunk;
    auto rvarvaAddrs = Descriptor->FirstThunk;

    if (!TableRvaInSection(Section, rvarvaNames)) return;
    if (IsBound && !TableRvaInSection(Section, rvarvaAddrs)) return;

    auto pNames = (TRva*)&base[rvarvaNames - Section->VirtualAddress];
    auto pAddrs = (TRva*)&base[rvarvaAddrs - Section->VirtualAddress];
    // Walk the rvas and zero out the addresses if possible.
    for (; *pNames != 0; pNames++, pAddrs++, rvarvaNames += sizeof(TRva), rvarvaAddrs += sizeof(TRva)) {
        if (!TableRvaInSection(Section, rvarvaNames)) continue;
        if (IsBound) {
            if (!TableRvaInSection(Section, rvarvaAddrs)) continue;
            *pAddrs = 0;
        }
        // Zero out the ordinals, in case ordinals changed but name didn't.
        auto name = *pNames;
        if ((name >> ((sizeof(TRva) * 8) - 1)) == 0) {
            // this value is really an RVA and not an import by ordinal, so if it's in this section it is safe to zero the hint
            if (!RvaInSection(Section, name, sizeof(IMAGE_IMPORT_BY_NAME))) continue;
            auto pImport = (PIMAGE_IMPORT_BY_NAME)&base[name - Section->VirtualAddress];
            pImport->Hint = 0;
        }
    }
}

// Relocate a PE section.
static void RelocateSectionPE(
    const byte* pBase,
    const PIMAGE_NT_HEADERS pPe,
    const PIMAGE_SECTION_HEADER pSects,
    const PIMAGE_DATA_DIRECTORY pDirReloc,
    byte* pRelocBuf,
    const ULONGLONG RelocatedBase,
    const ULONGLONG ImageBase,
    WORD sectionIdx)
{
    // Get the section of the relocation directory.
    WORD relocIdx = 0;
    for (; relocIdx < pPe->FileHeader.NumberOfSections; relocIdx++) {
        if (DirectoryInSection(&pSects[relocIdx], pDirReloc)) break;
    }
    if (relocIdx == pPe->FileHeader.NumberOfSections) return; // couldn't find it

    auto pReloc = &pBase[pSects[relocIdx].PointerToRawData + pDirReloc->VirtualAddress - pSects[relocIdx].VirtualAddress];
    auto pRelocEnd = &pReloc[pDirReloc->Size];

    const ULONGLONG Difference = RelocatedBase - ImageBase;
    const auto Machine = pPe->FileHeader.Machine;

    while (pReloc < pRelocEnd) {
        auto pBaseReloc = (PIMAGE_BASE_RELOCATION)pReloc;
        // is this RVA base inside the wanted section? if not, don't even bother processing relocation entries
        auto pNextReloc = &pReloc[pBaseReloc->SizeOfBlock];
        if (RvaInSection(&pSects[sectionIdx], pBaseReloc->VirtualAddress, 0)) {
            for (auto pRelocEntry = (PWORD)&pReloc[sizeof(*pBaseReloc)]; (SIZE_T)pRelocEntry < (SIZE_T)pNextReloc; pRelocEntry++) {
                auto type = (*pRelocEntry >> 12) & 0xf;
                auto offset = *pRelocEntry & 0xfff;

                auto pointer = &pRelocBuf[pBaseReloc->VirtualAddress + offset - pSects[sectionIdx].VirtualAddress];
                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // The base relocation is skipped. This type can be used to pad a block.
                    break;
                case IMAGE_REL_BASED_HIGH:
                    // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
                {
                    if (!RvaInSection(&pSects[sectionIdx], pBaseReloc->VirtualAddress + offset, sizeof(WORD))) continue;
                    UNALIGNED auto ptr16 = (PWORD)pointer;
                    ULONG val32 = (*ptr16 << 16) + (ULONG)Difference;
                    *ptr16 += (WORD)(val32 >> 16);
                    break;
                }
                case IMAGE_REL_BASED_LOW:
                    // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
                {
                    if (!RvaInSection(&pSects[sectionIdx], pBaseReloc->VirtualAddress + offset, sizeof(WORD))) continue;
                    UNALIGNED auto ptr16 = (PWORD)pointer;
                    ULONG val32 = *ptr16 + (ULONG)Difference;
                    *ptr16 += (WORD)(val32);
                    break;
                }
                case IMAGE_REL_BASED_HIGHLOW:
                    // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
                {
                    if (!RvaInSection(&pSects[sectionIdx], pBaseReloc->VirtualAddress + offset, sizeof(DWORD))) continue;
                    UNALIGNED auto ptr32 = (PDWORD)pointer;
                    *ptr32 += (ULONG)(Difference);
                    break;
                }
                case IMAGE_REL_BASED_HIGHADJ:
                    // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
                    // The 16-bit field represents the high value of a 32-bit word.
                    // The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
                    // This means that this base relocation occupies two slots.
                {
                    if (!RvaInSection(&pSects[sectionIdx], pBaseReloc->VirtualAddress + offset, sizeof(WORD))) continue;
                    UNALIGNED auto ptr16 = (PDWORD)pointer;
                    ULONG val32 = *ptr16 << 16;
                    pRelocEntry++;
                    if ((SIZE_T)pRelocEntry >= (SIZE_T)pNextReloc) continue; // invalid relocation entry?!
                    val32 += *pRelocEntry + (ULONG)Difference + 0x8000;
                    *ptr16 += (WORD)(val32 >> 16);
                    break;
                }
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
                {
                    // TODO: machine specific, ignore for now
                    break;
                }
                case IMAGE_REL_BASED_RESERVED:
                    break; // should never be encountered
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_7:
                {
                    // TODO: machine specific, ignore for now
                    break;
                }
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_8:
                {
                    // TODO: machine specific, ignore for now
                    break;
                }
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
                {
                    // TODO: machine specific, ignore for now
                    break;
                }
                case IMAGE_REL_BASED_DIR64:
                    // The base relocation applies the difference to the 64-bit field at offset.
                {
                    if (!RvaInSection(&pSects[sectionIdx], pBaseReloc->VirtualAddress + offset, sizeof(ULONGLONG))) continue;
                    UNALIGNED auto ptr64 = (PULONGLONG)pointer;
                    *ptr64 += Difference;
                    break;
                }

                }
            }

        }

        // increment pReloc to the next block
        pReloc = pNextReloc;
    }
}

// Compares PEs.
static UINT64 ComparePEs(const byte* p1, const UINT64 length1, const byte* p2, const UINT64 length2) {
    UINT64 ret = 0;
    auto pMz1 = (const PIMAGE_DOS_HEADER)p1;
    auto pMz2 = (const PIMAGE_DOS_HEADER)p2;
    auto pPe1 = (const PIMAGE_NT_HEADERS)&p1[pMz1->e_lfanew];
    auto pPe2 = (const PIMAGE_NT_HEADERS)&p2[pMz1->e_lfanew];
    // Ignore if optionalheader.magic / processor ids are different
    if (pPe1->OptionalHeader.Magic != pPe2->OptionalHeader.Magic) return COMPARE_IGNORE;
    if (pPe1->FileHeader.Machine != pPe2->FileHeader.Machine) return COMPARE_IGNORE;
    // If number of sections do not match return SectionCountDifferent
    if (pPe1->FileHeader.NumberOfSections != pPe2->FileHeader.NumberOfSections) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;

    // Get pointers to first section header
    auto pSect1 = (const PIMAGE_SECTION_HEADER)&p1[pMz1->e_lfanew + pPe1->FileHeader.SizeOfOptionalHeader + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)];
    auto pSect2 = (const PIMAGE_SECTION_HEADER)&p2[pMz2->e_lfanew + pPe2->FileHeader.SizeOfOptionalHeader + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)];

    static const DWORD CharacteristicsTable[] = {
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE, // .text
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA, // .rdata
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA, // .data
    };

    // Get the required image directories. Also get the ImageBase for both PEs.
    PIMAGE_DATA_DIRECTORY pDirRsrc1 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirRsrc2 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirReloc1 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirReloc2 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirDebug1 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirDebug2 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirExport1 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirExport2 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirImport1 = nullptr;
    PIMAGE_DATA_DIRECTORY pDirImport2 = nullptr;
    ULONGLONG ImageBase1 = 0;
    ULONGLONG ImageBase2 = 0;
    PULONGLONG ImageBaseToRelocate = nullptr;

    bool IsBound1 = false;
    bool IsBound2 = false;


    switch (pPe1->OptionalHeader.Magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        pDirRsrc1 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_RESOURCE);
        pDirRsrc2 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_RESOURCE);

        pDirReloc1 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_BASERELOC);
        pDirReloc2 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_BASERELOC);

        pDirDebug1 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_DEBUG);
        pDirDebug2 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_DEBUG);

        pDirExport1 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_EXPORT);
        pDirExport2 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_EXPORT);

        pDirImport1 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_IMPORT);
        pDirImport2 = GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_IMPORT);

        IsBound1 = !DirectoryIsNull(GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));
        IsBound2 = !DirectoryIsNull(GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

        ImageBase1 = GetImageBase<IMAGE_NT_HEADERS32>(pPe1);
        ImageBase2 = GetImageBase<IMAGE_NT_HEADERS32>(pPe2);
        break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        pDirRsrc1 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe1, IMAGE_DIRECTORY_ENTRY_RESOURCE);
        pDirRsrc2 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe2, IMAGE_DIRECTORY_ENTRY_RESOURCE);

        pDirReloc1 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe1, IMAGE_DIRECTORY_ENTRY_BASERELOC);
        pDirReloc2 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe2, IMAGE_DIRECTORY_ENTRY_BASERELOC);

        pDirDebug1 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe1, IMAGE_DIRECTORY_ENTRY_DEBUG);
        pDirDebug2 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe2, IMAGE_DIRECTORY_ENTRY_DEBUG);

        pDirExport1 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe1, IMAGE_DIRECTORY_ENTRY_EXPORT);
        pDirExport2 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe2, IMAGE_DIRECTORY_ENTRY_EXPORT);

        pDirImport1 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe1, IMAGE_DIRECTORY_ENTRY_IMPORT);
        pDirImport2 = GetDataDirectory<IMAGE_NT_HEADERS64>(pPe2, IMAGE_DIRECTORY_ENTRY_IMPORT);

        IsBound1 = !DirectoryIsNull(GetDataDirectory<IMAGE_NT_HEADERS32>(pPe1, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));
        IsBound2 = !DirectoryIsNull(GetDataDirectory<IMAGE_NT_HEADERS32>(pPe2, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

        ImageBase1 = GetImageBase<IMAGE_NT_HEADERS64>(pPe1);
        ImageBase2 = GetImageBase<IMAGE_NT_HEADERS64>(pPe2);
        break;
    }

    // Calculate the image base to relocate.
    // Basically: if ImageBase1 is NULL then relocate the first one if possible, otherwise relocate the second one if possible.
    if (ImageBase1 != ImageBase2) {
        if (ImageBase1 == 0 || (pDirReloc2->Size == 0 && pDirReloc1->Size != 0)) ImageBaseToRelocate = &ImageBase1;
        else if (pDirReloc2->Size != 0) ImageBaseToRelocate = &ImageBase2;
    }

    bool noSectionsCompared = true;
    bool noSectionsMatch = true;
    for (WORD i = 0; i < pPe1->FileHeader.NumberOfSections; i++) {
        // If section flags differ in each PE then return SectionCountDifferent
        if (pSect1[i].Characteristics != pSect2[i].Characteristics) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;

        // Skip the section if .rsrc
        if (DirectoryInSection(&pSect1[i], pDirRsrc1) || DirectoryInSection(&pSect2[i], pDirRsrc2)) {
            continue;
        }

#if 0
        // Skip the section if .reloc
        if (DirectoryInSection(&pSect1[i], pDirReloc1) || DirectoryInSection(&pSect2[i], pDirReloc2)) {
            sectionsSkipped++;
            continue;
        }
#endif

        // Calculate the section flag from the characteristics table.
        byte sectionFlag = 0;
        for (byte idx = 0; idx < sizeof(CharacteristicsTable) / sizeof(*CharacteristicsTable); idx++) {
            if ((pSect1[i].Characteristics & CharacteristicsTable[idx]) == CharacteristicsTable[idx]) {
                sectionFlag = BIT(idx);
                break;
            }
        }
        // If section flags differ from expected then skip the section
        if (sectionFlag == 0) {
            continue;
        }

        // Skip the section if it points outside the file
        if (pSect1[i].PointerToRawData + pSect1[i].SizeOfRawData > length1) continue;
        if (pSect2[i].PointerToRawData + pSect2[i].SizeOfRawData > length2) continue;

        SIZE_T Offset1 = pSect1[i].PointerToRawData;
        SIZE_T Offset2 = pSect2[i].PointerToRawData;
        SIZE_T Length = pSect1[i].SizeOfRawData;

        // If the section lengths are different then this section is different.
        if (Length != pSect2[i].SizeOfRawData) {
        SectionIsDifferent:
            noSectionsCompared = false;
            if (i < COMPARE_SECTION_BITS) ret |= BIT64(i);
            ret |= (((UINT64)sectionFlag) << COMPARE_SECTION_BITS);
            continue;
        }

        auto pData1 = &p1[Offset1];
        auto pData2 = &p2[Offset2];

        // If this section contains the debug directory then all data related to that will need to be zeroed.
        auto Debug1 = DirectoryInSection(&pSect1[i], pDirDebug1);
        auto Debug2 = DirectoryInSection(&pSect2[i], pDirDebug2);
        // If the debug directory isn't in the same section then return SectionCountDifferent
        if (Debug1 != Debug2) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;

        // If this section contains the export directory then its TimeDateStamp needs to be zeroed.
        auto Export1 = DirectoryInSection(&pSect1[i], pDirExport1);
        auto Export2 = DirectoryInSection(&pSect2[i], pDirExport2);
        // If the export directory isn't in the same section then return SectionCountDifferent
        if (Export1 != Export2) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;

        // If this section contains the import directory: the IAT needs to be zeroed.
        auto Import1 = DirectoryInSection(&pSect1[i], pDirImport1);
        auto Import2 = DirectoryInSection(&pSect2[i], pDirImport2);

        // If either are in this section, or image base doesn't match (therefore relocation might need to be performed) then reallocate.
        std::unique_ptr<BYTE[]> pAllocated1 = nullptr;
        std::unique_ptr<BYTE[]> pAllocated2 = nullptr;
        if (Debug1 || Export1 || Import1 || Import2) {
            // Needs reallocating.
            pAllocated1 = std::make_unique<BYTE[]>(Length);
            pAllocated2 = std::make_unique<BYTE[]>(Length);
            memcpy(pAllocated1.get(), pData1, Length);
            memcpy(pAllocated2.get(), pData2, Length);
            pData1 = pAllocated1.get();
            pData2 = pAllocated2.get();
        }
        else if (ImageBaseToRelocate != nullptr) {
            // Needs reallocating, but only for the relocated section.
            if (ImageBaseToRelocate == &ImageBase1) {
                pAllocated1 = std::make_unique<BYTE[]>(Length);
                memcpy(pAllocated1.get(), pData1, Length);
                pData1 = pAllocated1.get();
            }
            else {
                pAllocated2 = std::make_unique<BYTE[]>(Length);
                memcpy(pAllocated2.get(), pData2, Length);
                pData2 = pAllocated2.get();
            }
        }

        if (ImageBaseToRelocate != nullptr) {
            // Relocate the section.
            if (ImageBaseToRelocate == &ImageBase1) {
                RelocateSectionPE(p1, pPe1, pSect1, pDirReloc1, pAllocated1.get(), ImageBase2, ImageBase1, i);
            }
            else {
                RelocateSectionPE(p2, pPe2, pSect2, pDirReloc2, pAllocated2.get(), ImageBase1, ImageBase2, i);
            }
        }

        if (Export1) {
            // Zero out the timestamp in the export directory.
            auto pExport1 = (PIMAGE_EXPORT_DIRECTORY)&pAllocated1[pDirExport1->VirtualAddress - pSect1[i].VirtualAddress];
            auto pExport2 = (PIMAGE_EXPORT_DIRECTORY)&pAllocated2[pDirExport2->VirtualAddress - pSect2[i].VirtualAddress];

            pExport1->TimeDateStamp = 0;
            pExport2->TimeDateStamp = 0;
        }

        if (Import1) {
            // Zero out the IAT for first PE
            auto pImport = (const PIMAGE_IMPORT_DESCRIPTOR)&pAllocated1[pDirImport1->VirtualAddress - pSect1[i].VirtualAddress];
            
            for (SIZE_T desc = 0; desc < pDirImport1->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); desc++) {
                switch (pPe1->OptionalHeader.Magic) {
                case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    ClearIAT<UINT32>(pAllocated1.get(), &pSect1[i], &pImport[desc], IsBound1);
                    break;
                case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    ClearIAT<UINT64>(pAllocated1.get(), &pSect1[i], &pImport[desc], IsBound1);
                    break;
                }
            }
        }

        if (Import2) {
            // Zero out the IAT for second PE
            auto pImport = (const PIMAGE_IMPORT_DESCRIPTOR)&pAllocated2[pDirImport2->VirtualAddress - pSect2[i].VirtualAddress];

            for (SIZE_T desc = 0; desc < pDirImport2->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); desc++) {
                switch (pPe2->OptionalHeader.Magic) {
                case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    ClearIAT<UINT32>(pAllocated2.get(), &pSect2[i], &pImport[desc], IsBound2);
                    break;
                case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    ClearIAT<UINT64>(pAllocated2.get(), &pSect2[i], &pImport[desc], IsBound2);
                    break;
                }
            }
        }

        if (Debug1) {
            // Zero out all debug directory entries, then the debug directory itself.
            auto pDebugBlock1 = (PIMAGE_DEBUG_DIRECTORY)&pAllocated1[pDirDebug1->VirtualAddress - pSect1[i].VirtualAddress];
            auto pDebugBlock2 = (PIMAGE_DEBUG_DIRECTORY)&pAllocated2[pDirDebug2->VirtualAddress - pSect2[i].VirtualAddress];

            // Find the actual number of debug directories.
            // Some PEs have extra debug directories past what the PE header says.
            // There's always(?) a zerofilled entry to end, and to be sure we can check timestamp, all of them should match.
            // Use the value in the PE header to start with.
            SIZE_T debugBlockCount1 = pDirDebug1->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            SIZE_T debugBlockCount2 = pDirDebug2->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            while (true) {
                // Check if there's still space in this section, if not we know there's no more entries.
                SIZE_T wantedSize = (SIZE_T)&pDebugBlock1[debugBlockCount1] + sizeof(IMAGE_DEBUG_DIRECTORY) - (SIZE_T)pDebugBlock1;
                if (Length < wantedSize) break;

                // If the timestamp of this debug directory does not match the first one, there's no more entries.
                if (pDebugBlock1[0].TimeDateStamp != pDebugBlock1[debugBlockCount1].TimeDateStamp) break;

                // If this debug directory is all zero, there's no more entries.
                // No need to check that though, as the TimeDateStamp matches, so we know for sure it's not all-zero.

                // This entry looks valid, there's at least one more.
                debugBlockCount1++;
            }
            while (true) {
                // Check if there's still space in this section, if not we know there's no more entries.
                SIZE_T wantedSize = (SIZE_T)&pDebugBlock2[debugBlockCount2] + sizeof(IMAGE_DEBUG_DIRECTORY) - (SIZE_T)pDebugBlock2;
                if (Length < wantedSize) break;

                // If the timestamp of this debug directory does not match the first one, there's no more entries.
                if (pDebugBlock2[0].TimeDateStamp != pDebugBlock2[debugBlockCount2].TimeDateStamp) break;

                // If this debug directory is all zero, there's no more entries.
                // No need to check that though, as the TimeDateStamp matches, so we know for sure it's not all-zero.

                // This entry looks valid, there's at least one more.
                debugBlockCount2++;
            }

            // Walk through each of the debug directories. Zero out all debug blocks in this section.
            for (SIZE_T idx = 0; idx < debugBlockCount1; idx++) {
                // Ensure the debug directory contents are within this section.
                if (!DirectoryInSection(&pSect1[i], &pDebugBlock1[idx])) continue;

                if (pDebugBlock1[idx].AddressOfRawData == 0) {
                    if (pDebugBlock1[idx].PointerToRawData == 0) continue;
                    memset(&pAllocated1[(SIZE_T)pDebugBlock1[idx].PointerToRawData - pSect1[i].PointerToRawData], 0, pDebugBlock1[idx].SizeOfData);
                    continue;
                }
                memset(&pAllocated1[(SIZE_T)pDebugBlock1[idx].AddressOfRawData - pSect1[i].VirtualAddress], 0, pDebugBlock1[idx].SizeOfData);
            }
            memset(pDebugBlock1, 0, debugBlockCount1 * sizeof(IMAGE_DEBUG_DIRECTORY));

            for (SIZE_T idx = 0; idx < debugBlockCount2; idx++) {
                // Ensure the debug directory contents are within this section.
                if (!DirectoryInSection(&pSect2[i], &pDebugBlock2[idx])) continue;

                if (pDebugBlock2[idx].AddressOfRawData == 0) {
                    if (pDebugBlock2[idx].PointerToRawData == 0) continue;
                    memset(&pAllocated2[(SIZE_T)pDebugBlock2[idx].PointerToRawData - pSect2[i].PointerToRawData], 0, pDebugBlock2[idx].SizeOfData);
                    continue;
                }
                memset(&pAllocated2[(SIZE_T)pDebugBlock2[idx].AddressOfRawData - pSect2[i].VirtualAddress], 0, pDebugBlock2[idx].SizeOfData);
            }
            memset(pDebugBlock2, 0, debugBlockCount2 * sizeof(IMAGE_DEBUG_DIRECTORY));
        }
        // Compare the data, if not equal then set the flag
        if (memcmp(pData1, pData2, Length) != 0) goto SectionIsDifferent;

        // Sections are equal, so at least one section matches.
        noSectionsMatch = false;
    }
    if (noSectionsCompared) noSectionsMatch = false;
    if (noSectionsMatch) ret |= COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    return ret;
}

// Compares NEs.
static UINT64 CompareNEs(const byte* p1, const UINT64 length1, const byte* p2, const UINT64 length2) {
    UINT64 ret = 0;
    auto pMz1 = (const PIMAGE_DOS_HEADER)p1;
    auto pMz2 = (const PIMAGE_DOS_HEADER)p2;
    auto pNe1 = (const PIMAGE_OS2_HEADER)&p1[pMz1->e_lfanew];
    auto pNe2 = (const PIMAGE_OS2_HEADER)&p2[pMz1->e_lfanew];

    // Ignore if target OS is different.
    if (pNe1->ne_exetyp != pNe2->ne_exetyp) return COMPARE_IGNORE;
    // If number of sections do not match return SectionCountDifferent
    if (pNe1->ne_cseg != pNe2->ne_cseg) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    // If there are no sections, nothing needs to be done.
    if (pNe1->ne_cseg == 0) return COMPARE_IGNORE;

    // Get pointers to first section header
    auto pSect1 = (const PNE_SECTION_HEADER)&p1[pMz1->e_lfanew + pNe1->ne_segtab];
    auto pSect2 = (const PNE_SECTION_HEADER)&p2[pMz2->e_lfanew + pNe2->ne_segtab];

    static const WORD CharacteristicsTable[] = {
        0, // .text
        NE_SEGMENT_IS_DATA | NE_SEGMENT_READ_EXEC_ONLY, // .rdata
        NE_SEGMENT_IS_DATA // .data
    };

    bool noSectionsMatch = true;
    for (WORD i = 0; i < pNe1->ne_cseg; i++) {
        // If section flags differ then return SectionCountDifferent
        auto flags1 = pSect1[i].Flags & (NE_SEGMENT_IS_DATA | NE_SEGMENT_READ_EXEC_ONLY);
        {
            auto flags2 = pSect2[i].Flags & (NE_SEGMENT_IS_DATA | NE_SEGMENT_READ_EXEC_ONLY);
            if (flags1 != flags2) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
        }

        // Calculate the section flag.
        byte sectionFlag = 0;
        for (byte idx = 0; idx < sizeof(CharacteristicsTable) / sizeof(*CharacteristicsTable); idx++) {
            if (flags1 == CharacteristicsTable[idx]) {
                sectionFlag = BIT(idx);
                break;
            }
        }
        if (sectionFlag == 0 && flags1 == NE_SEGMENT_READ_EXEC_ONLY) sectionFlag = COMPARE_DIFF_CODE;
        // If section flags differ from expected then skip the section
        if (sectionFlag == 0) continue;

        // Calculate the section data offsets
        auto DataOffset1 = ((SIZE_T)pSect1[i].DataSector << pNe1->ne_align);
        auto DataOffset2 = ((SIZE_T)pSect2[i].DataSector << pNe2->ne_align);

        // Skip the section if it points outside the file
        if (DataOffset1 + pSect1[i].DataLength > length1) continue;
        if (DataOffset2 + pSect2[i].DataLength > length2) continue;

        // Compare the section length and bytes, if either differ then set the flag
        if (
            (pSect1[i].DataLength != pSect2[i].DataLength) ||
            (memcmp(&p1[DataOffset1], &p2[DataOffset2], pSect1[i].DataLength) != 0)
            ) {
            if (i < COMPARE_SECTION_BITS) ret |= BIT64(i);
            ret |= (((UINT64)sectionFlag) << COMPARE_SECTION_BITS);
        }
        else noSectionsMatch = false;
    }
    if (noSectionsMatch) ret |= COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    return ret;
}

// Compares LEs.
static UINT64 CompareLEs(const byte* p1, const UINT64 length1, const byte* p2, const UINT64 length2) {
    UINT64 ret = 0;
    auto pMz1 = (const PIMAGE_DOS_HEADER)p1;
    auto pMz2 = (const PIMAGE_DOS_HEADER)p2;
    auto pLe1 = (const PIMAGE_VXD_HEADER)&p1[pMz1->e_lfanew];
    auto pLe2 = (const PIMAGE_VXD_HEADER)&p2[pMz1->e_lfanew];

    // Ignore if target OS is different.
    // Only care about CPU if one is 286 and other is not.
    if (pLe1->e32_os != pLe2->e32_os) return COMPARE_IGNORE;
    if (pLe1->e32_cpu != pLe2->e32_cpu && (pLe1->e32_cpu == LE_CPU_286 || pLe2->e32_cpu == LE_CPU_286)) return COMPARE_IGNORE;
    // If number of sections do not match return SectionCountDifferent
    if (pLe1->e32_objcnt != pLe2->e32_objcnt) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    // If there are no sections, nothing needs to be done
    if (pLe1->e32_objcnt == 0) return COMPARE_IGNORE;

    // Get pointers to first section header
    auto pSect1 = (const PLE_SECTION_HEADER)&p1[pMz1->e_lfanew + pLe1->e32_objtab];
    auto pSect2 = (const PLE_SECTION_HEADER)&p2[pMz2->e_lfanew + pLe2->e32_objtab];


    static const WORD CharacteristicsTable[] = {
        LE_SECTION_MEM_READ | LE_SECTION_MEM_EXEC, // .text
        LE_SECTION_MEM_READ, // .rdata
        LE_SECTION_MEM_READ | LE_SECTION_MEM_WRITE // .data
    };

    bool noSectionsMatch = true;
    for (WORD i = 0; i < pLe1->e32_objcnt; i++) {
        // If section flags differ then return SectionCountDifferent
        auto flags1 = pSect1[i].Flags & (LE_SECTION_MEM_READ | LE_SECTION_MEM_WRITE | LE_SECTION_MEM_EXEC | LE_SECTION_ALIAS16);
        {
            auto flags2 = pSect2[i].Flags & (LE_SECTION_MEM_READ | LE_SECTION_MEM_WRITE | LE_SECTION_MEM_EXEC | LE_SECTION_ALIAS16);
            if (flags1 != flags2) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
        }
        flags1 &= ~LE_SECTION_ALIAS16;

        // Calculate the section flag.
        byte sectionFlag = 0;
        for (byte idx = 0; idx < sizeof(CharacteristicsTable) / sizeof(*CharacteristicsTable); idx++) {
            if (flags1 == CharacteristicsTable[idx]) {
                sectionFlag = BIT(idx);
                break;
            }
        }
        if (sectionFlag == 0 && (flags1 & CharacteristicsTable[0]) != 0) sectionFlag = COMPARE_DIFF_CODE;
        // If section flags differ from expected then skip the section
        if (sectionFlag == 0) continue;

        // Calculate the section data offsets
        // This apparently works fine according to openwatcom exedump
        auto DataOffset1 = ((SIZE_T)pSect1[i].PageTableIndex * pLe1->e32_pagesize) + pLe1->e32_datapage;
        auto DataOffset2 = ((SIZE_T)pSect2[i].PageTableIndex * pLe2->e32_pagesize) + pLe2->e32_datapage;

        // Skip the section if it points outside the file
        if (DataOffset1 + pSect1[i].VirtualSize > length1) continue;
        if (DataOffset2 + pSect2[i].VirtualSize > length2) continue;

        // Compare the section length and bytes, if either differ then set the flag
        if (
            (pSect1[i].VirtualSize != pSect2[i].VirtualSize) ||
            (memcmp(&p1[DataOffset1], &p2[DataOffset2], pSect1[i].VirtualSize) != 0)
            ) {
            if (i < COMPARE_SECTION_BITS) ret |= BIT64(i);
            ret |= (((UINT64)sectionFlag) << COMPARE_SECTION_BITS);
        }
        else noSectionsMatch = false;
    }
    if (noSectionsMatch) ret |= COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    return ret;
}

// Compares LXs.
static UINT64 CompareLXs(const byte* p1, const UINT64 length1, const byte* p2, const UINT64 length2) {
    // Returns: bit 0 set if .text is different, bit 1 set if .rdata is different (if present), bit 2 set if .data is different (if present), bit 3 if number of sections different
    UINT64 ret = 0;
    auto pMz1 = (const PIMAGE_DOS_HEADER)p1;
    auto pMz2 = (const PIMAGE_DOS_HEADER)p2;
    auto pLe1 = (const PIMAGE_VXD_HEADER)&p1[pMz1->e_lfanew];
    auto pLe2 = (const PIMAGE_VXD_HEADER)&p2[pMz1->e_lfanew];

    // Ignore if target OS is different.
    // Only care about CPU if one is 286 and other is not.
    if (pLe1->e32_os != pLe2->e32_os) return COMPARE_IGNORE;
    if (pLe1->e32_cpu != pLe2->e32_cpu && (pLe1->e32_cpu == LE_CPU_286 || pLe2->e32_cpu == LE_CPU_286)) return COMPARE_IGNORE;
    // If number of sections do not match return SectionCountDifferent
    if (pLe1->e32_objcnt != pLe2->e32_objcnt) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    // If there are no sections, nothing needs to be done
    if (pLe1->e32_objcnt == 0) return COMPARE_IGNORE;

    // Get pointers to first section header
    auto pSect1 = (const PLE_SECTION_HEADER)&p1[pMz1->e_lfanew + pLe1->e32_objtab];
    auto pSect2 = (const PLE_SECTION_HEADER)&p2[pMz2->e_lfanew + pLe2->e32_objtab];


    static const WORD CharacteristicsTable[] = {
        LE_SECTION_MEM_READ | LE_SECTION_MEM_EXEC, // .text
        LE_SECTION_MEM_READ, // .rdata
        LE_SECTION_MEM_READ | LE_SECTION_MEM_WRITE // .data
    };

    bool noSectionsMatch = true;
    for (WORD i = 0; i < pLe1->e32_objcnt; i++) {
        // If section flags differ then return SectionCountDifferent
        auto flags1 = pSect1[i].Flags & (LE_SECTION_MEM_READ | LE_SECTION_MEM_WRITE | LE_SECTION_MEM_EXEC | LE_SECTION_ALIAS16);
        {
            auto flags2 = pSect2[i].Flags & (LE_SECTION_MEM_READ | LE_SECTION_MEM_WRITE | LE_SECTION_MEM_EXEC | LE_SECTION_ALIAS16);
            if (flags1 != flags2) return COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
        }
        flags1 &= ~LE_SECTION_ALIAS16;

        // Calculate the section flag.
        byte sectionFlag = 0;
        for (byte idx = 0; idx < sizeof(CharacteristicsTable) / sizeof(*CharacteristicsTable); idx++) {
            if (flags1 == CharacteristicsTable[idx]) {
                sectionFlag = BIT(idx);
                break;
            }
        }
        if (sectionFlag == 0 && (flags1 & CharacteristicsTable[0]) != 0) sectionFlag = COMPARE_DIFF_CODE;
        // If section flags differ from expected then skip the section
        if (sectionFlag == 0) continue;

        // Calculate the section data offsets
        // This apparently works fine according to openwatcom exedump
        // In LX, e32_lastpagesize is really e32_pageoffsetshift
        auto DataOffset1 = ((SIZE_T)pSect1[i].PageTableIndex << pLe1->e32_lastpagesize) + pLe1->e32_datapage;
        auto DataOffset2 = ((SIZE_T)pSect2[i].PageTableIndex << pLe2->e32_lastpagesize) + pLe2->e32_datapage;

        // Skip the section if it points outside the file
        if (DataOffset1 + pSect1[i].VirtualSize > length1) continue;
        if (DataOffset2 + pSect2[i].VirtualSize > length2) continue;

        // Compare the section length and bytes, if either differ then set the flag
        if (
            (pSect1[i].VirtualSize != pSect2[i].VirtualSize) ||
            (memcmp(&p1[DataOffset1], &p2[DataOffset2], pSect1[i].VirtualSize) != 0)
            ) {
            if (i < COMPARE_SECTION_BITS) ret |= BIT64(i);
            ret |= (((UINT64)sectionFlag) << COMPARE_SECTION_BITS);
        }
        else noSectionsMatch = false;
    }
    if (noSectionsMatch) ret |= COMPARE_DIFF_SECTIONS << COMPARE_SECTION_BITS;
    return ret;
}

// Compares executable files.
static UINT64 CompareExes(const byte type, const byte* p1, const UINT64 length1, const byte* p2, const UINT64 length2) {
    switch (type) {
    case EXECUTABLE_NE:
        return CompareNEs(p1, length1, p2, length2);
    case EXECUTABLE_LE:
        return CompareLEs(p1, length1, p2, length2);
    case EXECUTABLE_LX:
        return CompareLXs(p1, length1, p2, length2);
    case EXECUTABLE_PE:
        return ComparePEs(p1, length1, p2, length2);
    case EXECUTABLE_UNKNOWN:
    default:
        return COMPARE_IGNORE;
    }
}

// Determines if files are PEs
static bool IsPECore(const UINT8* pBytes, const UINT64 length) {
    auto pMz = (const PIMAGE_DOS_HEADER)pBytes;
    auto pPe = (const PIMAGE_NT_HEADERS)&pBytes[pMz->e_lfanew];
    // bounds check PE header
    if (pMz->e_lfanew > length) return false;
    if ((UINT64)(pMz->e_lfanew) + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + sizeof(WORD) >= length) return false;
    // check PE header
    if (pPe->Signature != IMAGE_NT_SIGNATURE) return false;
    // bounds check optional header size, must at least have Magic element
    if (pPe->FileHeader.SizeOfOptionalHeader < offsetof(IMAGE_OPTIONAL_HEADER32, MajorLinkerVersion)) return false;
    auto OptionalMagic = pPe->OptionalHeader.Magic;
    // check optional header
    if (OptionalMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    // bounds check optional and section headers
    if ((UINT64)(pMz->e_lfanew) + pPe->FileHeader.SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * pPe->FileHeader.NumberOfSections) > length) return false;
    return true;
}

// Determines if files are NEs
static bool IsNECore(const UINT8* pBytes, const UINT64 length) {
    auto pMz = (const PIMAGE_DOS_HEADER)pBytes;
    auto pNe = (const PIMAGE_OS2_HEADER)&pBytes[pMz->e_lfanew];
    // bounds check NE header
    if ((UINT64)(pMz->e_lfanew) + sizeof(IMAGE_OS2_HEADER) >= length) return false;
    // check NE header
    if (pNe->ne_magic != IMAGE_OS2_SIGNATURE) return false;
    // bounds check section headers
    if (((UINT64)pMz->e_lfanew) + pNe->ne_segtab + (sizeof(NE_SECTION_HEADER) * pNe->ne_cseg) > length) return false;
    return true;
}

// Determines if files are LEs
static bool IsLECore(const UINT8* pBytes, const UINT64 length) {
    auto pMz = (const PIMAGE_DOS_HEADER)pBytes;
    auto pLe = (const PIMAGE_VXD_HEADER)&pBytes[pMz->e_lfanew];
    // bounds check LE header
    if ((UINT64)(pMz->e_lfanew) + sizeof(IMAGE_VXD_HEADER) >= length) return false;
    // check LE header
    if (pLe->e32_magic != IMAGE_VXD_SIGNATURE) return false;
    // bounds check section headers
    if (((UINT64)pMz->e_lfanew) + pLe->e32_objtab + (sizeof(LE_SECTION_HEADER) * pLe->e32_objcnt) > length) return false;
    return true;
}

// Determines if files are LXs
static bool IsLXCore(const UINT8* pBytes, const UINT64 length) {
    auto pMz = (const PIMAGE_DOS_HEADER)pBytes;
    auto pLe = (const PIMAGE_VXD_HEADER)&pBytes[pMz->e_lfanew];
    // bounds check LE header
    if ((UINT64)(pMz->e_lfanew) + sizeof(IMAGE_VXD_HEADER) >= length) return false;
    // check LE header
    if (pLe->e32_magic != IMAGE_LX_SIGNATURE) return false;
    // bounds check section headers
    if (((UINT64)pMz->e_lfanew) + pLe->e32_objtab + (sizeof(LE_SECTION_HEADER) * pLe->e32_objcnt) > length) return false;
    return true;
}

using TFExecutableCore = bool(const UINT8*, const UINT64);

// Determines if an MZ file is a specific newer executable
template <TFExecutableCore FuncCore> static bool IsExecutable(const UINT8* pBytes, const UINT64 length) {
    auto pMz = (const PIMAGE_DOS_HEADER)pBytes;
    // check MZ header
    if (length < sizeof(IMAGE_DOS_HEADER)) return false;
    if (pMz->e_magic != IMAGE_DOS_SIGNATURE) return false;
    return FuncCore(pBytes, length);
}

// Determines if files are PEs
inline static bool IsPE(const UINT8* pBytes, const UINT64 length) {
    return IsExecutable<IsPECore>(pBytes, length);
}

// Determines if files are NEs
inline static bool IsNE(const UINT8* pBytes, const UINT64 length) {
    return IsExecutable<IsNECore>(pBytes, length);
}

// Determines if files are LEs
inline static bool IsLE(const UINT8* pBytes, const UINT64 length) {
    return IsExecutable<IsLECore>(pBytes, length);
}

// Determines if files are LXs
inline static bool IsLX(const UINT8* pBytes, const UINT64 length) {
    return IsExecutable<IsLXCore>(pBytes, length);
}

// Gets the executable type.
static byte GetExecutableType(const UINT8* pBytes, const UINT64 length) {
    // If it doesn't have a valid DOS header with a valid e_lfanew, then it's not an executable file.
    auto pMz = (const PIMAGE_DOS_HEADER)pBytes;
    // check MZ header
    if (sizeof(*pMz) > length) return false;
    if (pMz->e_magic != IMAGE_DOS_SIGNATURE) return EXECUTABLE_UNKNOWN;
    if (pMz->e_lfanew == 0 || pMz->e_lfanew > length) return EXECUTABLE_UNKNOWN;

    if (IsNECore(pBytes, length)) return EXECUTABLE_NE;
    if (IsLECore(pBytes, length)) return EXECUTABLE_LE;
    if (IsLXCore(pBytes, length)) return EXECUTABLE_LX;
    if (IsPECore(pBytes, length)) return EXECUTABLE_PE;
    return EXECUTABLE_UNKNOWN;
}

#pragma managed(pop)

using namespace System;
using namespace System::IO;
using namespace System::IO::MemoryMappedFiles;
using namespace Microsoft::Win32::SafeHandles;

// Gets a pointer from a SafeMemoryMappedViewHandle
static Byte* GetPointer(SafeMemoryMappedViewHandle^ hView) {
    Byte* ret = nullptr;
    hView->AcquirePointer(ret);
    if (ret == nullptr) return nullptr;
    // ReleasePointer() just decrefs, our pointer is still valid after this...
    hView->ReleasePointer();
    return ret;
}

// Scoped memory mapped view with RAII
ref struct ScopedMemoryMappedView {
private:
    MemoryMappedFile^ m_file;
    MemoryMappedViewAccessor^ m_accessor;

public:
    ScopedMemoryMappedView(String^ filename) {
        m_file = MemoryMappedFile::CreateFromFile(
            File::OpenRead(filename),
            nullptr,
            0,
            MemoryMappedFileAccess::Read,
            HandleInheritability::None,
            false
        );
        m_accessor = m_file->CreateViewAccessor(0, 0, MemoryMappedFileAccess::Read);
    }

    ~ScopedMemoryMappedView() {
        m_accessor->~MemoryMappedViewAccessor();
        m_file->~MemoryMappedFile();
    }

    property SafeMemoryMappedViewHandle^ View {
        SafeMemoryMappedViewHandle^ get() { return m_accessor->SafeMemoryMappedViewHandle; }
    }

    property UInt64 ByteLength {
        UInt64 get() { return View->ByteLength; }
    }

    static operator SafeMemoryMappedViewHandle^ (ScopedMemoryMappedView% mapped) {
        return mapped.View;
    }
};

static void DiffFiles(String^ dir1, String^ dir2, String^ baseFolder) {
    for each (auto file in Directory::EnumerateFiles(dir1)) {
        // Calculate the path of the filename in the second directory. If it doesn't exist then skip it.
        auto fileName = file->Substring(dir1->Length + 1);
        auto file2 = Path::Combine(dir2, fileName);
        if (!File::Exists(file2)) continue;

        UINT64 result = COMPARE_IGNORE;
        byte type = EXECUTABLE_UNKNOWN;
        try {
            // Map the file in the first directory and get a pointer to it
            ScopedMemoryMappedView hView(file);
            auto pBytes = GetPointer(hView);
            type = GetExecutableType(pBytes, hView.ByteLength);
            // If it's not PE/NE/LE then skip it.
            if (type != EXECUTABLE_UNKNOWN) {

                // Map the file in the second directory and get a pointer to it
                ScopedMemoryMappedView hView2(file2);
                auto pBytes2 = GetPointer(hView2);
                // If the executable type doesn't match the first file then skip it.
                if (GetExecutableType(pBytes2, hView2.ByteLength) == type) {
                    // Compare the two executables.
                    result = CompareExes(type, pBytes, hView.ByteLength, pBytes2, hView2.ByteLength);
                }
            }
        }
        catch (Exception^) { continue; }

        // If they match, or either file was not a PE, then skip printing anything.
        if (result == COMPARE_IGNORE) continue;

        // Print the type, filename, and what was different.
        switch (type) {
        case EXECUTABLE_NE:
            Console::Write("[NE] ");
            break;
        case EXECUTABLE_LE:
            Console::Write("[LE] ");
            break;
        case EXECUTABLE_LX:
            Console::Write("[LX] ");
            break;
        case EXECUTABLE_PE:
            Console::Write("[PE] ");
            break;
        }
        Console::Write(Path::Combine(baseFolder, fileName));
        Console::Write(": ");
        byte resultTypes = (result >> COMPARE_SECTION_BITS);
        if ((resultTypes & COMPARE_DIFF_CODE) != 0) Console::Write("text ");
        if ((resultTypes & COMPARE_DIFF_RDATA) != 0) Console::Write("rdata ");
        if ((resultTypes & COMPARE_DIFF_DATA) != 0) Console::Write("data ");
        if (resultTypes == COMPARE_DIFF_SECTIONS) Console::Write("sections");
        else if ((resultTypes & COMPARE_DIFF_SECTIONS) != 0) Console::Write("(all)");
        else {
            Console::Write(L'(');
            bool first = true;
            for (int i = 0; i < COMPARE_SECTION_BITS; i++) {
                if (result & 1) {
                    if (!first) Console::Write(", ");
                    Console::Write(i);
                    first = false;
                }
                result >>= 1;
            }
            Console::Write(L')');
        }
        Console::WriteLine();
    }
}

enum {
    WIXSXS_DIR_PARTS_LENGTH = 6,
    WINSXS_HASH_HEXITS_LENGTH = 16,
    WINSXS_EARLY_DIR_PARTS_LENGTH = 2,
    WIXSXS_EARLY_HASH_HEXITS_LENGTH = 8
};

// Diffs all executable files in two directories
static void Diff(String^ dir1, String^ dir2, String^ baseFolder = String::Empty) {
    for each (auto folder in Directory::EnumerateDirectories(dir1)) {
        // Calculate the path of the folder name in the second directory. If it doesn't exist then skip it.
        auto folderName = folder->Substring(dir1->Length + 1);
        auto folder2 = Path::Combine(dir2, folderName);
        if (!Directory::Exists(folder2)) {
            // Does this look like a winsxs package directory?
            auto winsxs = folderName->Split(L'_');
            // arch_name_hash_version_lang_hash
            if (winsxs->Length >= WIXSXS_DIR_PARTS_LENGTH) {
                if (winsxs[winsxs->Length - 1]->Length != WINSXS_HASH_HEXITS_LENGTH) continue;
                if (winsxs[winsxs->Length - 4]->Length != WINSXS_HASH_HEXITS_LENGTH) continue;
                // set up the search wildcard
                winsxs[winsxs->Length - 1] = "*";
                winsxs[winsxs->Length - 3] = "*";
            }
            // name_hash, earlier-style unstaged WIM dirnames
            else if (winsxs->Length >= WINSXS_EARLY_DIR_PARTS_LENGTH) {
                if (winsxs[winsxs->Length - 1]->Length != WIXSXS_EARLY_HASH_HEXITS_LENGTH) continue;
                // set up the search wildcard
                winsxs[winsxs->Length - 1] = "*";
            }
            else {
                continue;
            }
            auto winsxsStr = String::Join("_", winsxs);
            auto dirs = Directory::GetDirectories(dir2, winsxsStr);
            // there might be more than one directory found, if some winsxs dirs are being compared.
            // this functionality is for comparing update packages or unstaged WIMs
            if (dirs->Length != 1) continue;
            Diff(folder, dirs[0], Path::Combine(baseFolder, winsxsStr));
            continue;
        }

        // Recurse into this directory.
        Diff(folder, folder2, Path::Combine(baseFolder, folderName));
    }
    DiffFiles(dir1, dir2, baseFolder);
}

static void Diff(const wchar_t* dir1, const wchar_t* dir2) {
    Diff(gcnew String(dir1), gcnew String(dir2));
}

#pragma managed(push, off)

int wmain(int argc, const wchar_t** argv)
{
    if (argc <= 2) {
        //Console::WriteLine("Usage: {0} <dir1> <dir2>", System::Reflection::Assembly::GetEntryAssembly()->Location);
        wprintf(L"Usage: %s <dir1> <dir2>", argv[0]);
        return 0;
    }

    Diff(argv[1], argv[2]);
    return 0;
}