// Author : garjulia

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include <map>
#include <ctime>

using namespace std;

enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_RED = 12,
    COLOR_GREEN = 10,
    COLOR_YELLOW = 14,
    COLOR_CYAN = 11,
    COLOR_MAGENTA = 13 
};

void setColor(ConsoleColor c) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)c);
}

void printBanner() {
    setColor(COLOR_CYAN);
    cout << "  ____  _      __           _    _             _            \n";
    cout << " / __ \\| |    / _|         | |  | |           | |           \n";
    cout << "| |  | | |__ | |_ _   _ ___| |__| |_   _ _ __ | |_ ___ _ __ \n";
    cout << "| |  | | '_ \\|  _| | | / __|  __  | | | | '_ \\| __/ _ \\ '__|\n";
    cout << "| |__| | |_) | | | |_| \\__ \\ |  | | |_| | | | | ||  __/ |   \n";
    cout << " \\____/|_.__/|_|  \\__,_|___/_|  |_|\\__,_|_| |_|\\__\\___|_|   \n\n";
    setColor(COLOR_DEFAULT);
}

struct Match {
    DWORD rva;
    DWORD offset;
    string category;
    string detail;
    bool isStrong;
};

bool matchPattern(const unsigned char* buf, size_t size, const vector<int>& pat) {
    if (pat.size() > size) return false;
    for (size_t j = 0; j < pat.size(); ++j) {
        if (pat[j] != -1 && buf[j] != (unsigned char)pat[j]) return false;
    }
    return true;
}

vector<size_t> findPatterns(const unsigned char* buf, size_t size, const vector<int>& pat) {
    vector<size_t> results;
    if (pat.size() > size) return results;
    for (size_t i = 0; i <= size - pat.size(); ++i) {
        if (matchPattern(buf + i, size - i, pat)) results.push_back(i);
    }
    return results;
}

int main(int argc, char* argv[]) {
    printBanner();

    if (argc < 2) {
        setColor(COLOR_YELLOW);
        cout << "Usage: ObfusHunter.exe <path_to_pe_file>\n";
        setColor(COLOR_DEFAULT);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        setColor(COLOR_RED); cout << "[-] Cannot open file.\n"; setColor(COLOR_DEFAULT);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pBase = hMap ? MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0) : NULL;
    if (!pBase) {
        setColor(COLOR_RED); cout << "[-] Cannot map file.\n"; setColor(COLOR_DEFAULT); // жир гпт
        if (hMap) CloseHandle(hMap); CloseHandle(hFile); return 1;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    int numSections = nt->FileHeader.NumberOfSections;

    cout << "[ File Information ]\n";
    cout << " Path:       " << argv[1] << "\n";
    cout << " Size:       " << fileSize << " bytes\n";
    cout << " Arch:       " << (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86") << "\n";
    cout << " EntryPoint: 0x" << hex << nt->OptionalHeader.AddressOfEntryPoint << dec << "\n";

    vector<Match> matches;
    bool hasStrongIndicator = false;

    auto RvaToOff = [&](DWORD rva) -> DWORD {
        for (int i = 0; i < numSections; i++) {
            auto& s = sections[i];
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc.VirtualSize))
                return rva - s.VirtualAddress + s.PointerToRawData;
        }
        return 0;
        };

    auto AddMatch = [&](DWORD rva, DWORD off, string cat, string det, bool strong) {
        matches.push_back({ rva, off, cat, det, strong });
        if (strong) hasStrongIndicator = true;
        };

    /*
    TCC detection
    https://bellard.org/tcc/
    */

    //rules: https://github.com/horsicq/Detect-It-Easy/blob/master/db%2FPE%2Fcompiler_tcc.6.sg
    bool isTCC = false;
    vector<int> tccDosStub = {
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
        0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00
    };

    if (matchPattern((unsigned char*)pBase, fileSize, tccDosStub) &&
        nt->OptionalHeader.MajorLinkerVersion == 6 && nt->OptionalHeader.MinorLinkerVersion == 0) {
        isTCC = true;
        AddMatch(0, 0, "Compiler", "Tiny C (TCC) detected by Linker/Stub", true);
    }

    // EP patterns for TCC
    if (isTCC) {
        DWORD epOff = RvaToOff(nt->OptionalHeader.AddressOfEntryPoint);
        if (epOff && epOff < fileSize) {
            unsigned char* epPtr = (unsigned char*)pBase + epOff;
            size_t remaining = fileSize - epOff;

            vector<int> tcc_x64_ep = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, -1, -1, -1, -1, 0xB8, -1, -1, -1, -1, 0x89, 0x45, -1, 0xB8, -1, -1, -1, -1, 0x49, 0x89, 0xC2, 0x4C, 0x89, 0xD1, 0xE8 };
            vector<int> tcc_x86_ep = { 0x55, 0x89, 0xE5, 0x81, 0xEC, -1, -1, -1, -1, 0x90, 0x8D, 0x45, -1, 0x50, 0xE8, -1, -1, -1, -1, 0x83, 0xC4, -1, 0xB8, -1, -1, -1, -1, 0x89, 0x45, -1, 0xB8, -1, -1, -1, -1, 0x50, 0xE8, -1, -1, -1, -1, 0x83, 0xC4 };
            vector<int> tcc_legacy_ep = { 0x55, 0x89, 0xE5, 0x81, 0xEC, -1, -1, -1, -1, 0x90, 0xE8 };

            if (matchPattern(epPtr, remaining, tcc_x64_ep)) AddMatch(nt->OptionalHeader.AddressOfEntryPoint, epOff, "Compiler", "TCC x64 EntryPoint", true);
            else if (matchPattern(epPtr, remaining, tcc_x86_ep)) AddMatch(nt->OptionalHeader.AddressOfEntryPoint, epOff, "Compiler", "TCC x86 EntryPoint", true);
            else if (matchPattern(epPtr, remaining, tcc_legacy_ep)) AddMatch(nt->OptionalHeader.AddressOfEntryPoint, epOff, "Compiler", "TCC Legacy EntryPoint", true);
        }
    }

    struct SigDef { string name; vector<int> pat; string cat; bool strong; };
    vector<SigDef> sigs = {
        // junk code
        {"BREAK_STACK_1", {0x31, 0xC0, 0x74, 0x01, 0xE8, 0x0F, 0xA2}, "Junk Code", true},
        {"BREAK_STACK_4", {0x31, 0xDB, 0x31, 0xD2, 0x31, 0xDA, 0x74, 0x06, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xA2}, "Junk Code", true},
        {"BREAK_STACK_5", {0x31, 0xDB, 0x31, 0xC0, 0x89, 0xC3, 0x89, 0xD3, 0x31, 0xC2, 0x74, 0x01, 0x20, 0x0F, 0xA2}, "Junk Code", true},
        {"BREAK_STACK_6", {0x31, 0xD2, 0x31, 0xC0, 0x89, 0xC2, 0x74, 0x01, 0xE8, 0x0F, 0xA2}, "Junk Code", true},
        {"BREAK_STACK_7", {0x31, 0xD2, 0x74, 0x01, 0xE8, 0x0F, 0xA2}, "Junk Code", true},
        {"BREAK_STACK_8", {0x31, 0xC0, 0x74, 0x01, 0x50, 0x0F, 0xA2}, "Junk Code", true},
        {"BREAK_STACK_9", {0x31, 0xD2, 0x74, 0x02, 0x00, 0x00, 0x0F, 0xA2}, "Junk Code", true},

        // anti-debug
        {"AD_DR_CLEAN", {0x31, -1, 0x89, -1, 0x00, 0x89, -1, 0x04, 0x89, -1, 0x08, 0x89, -1, 0x0C}, "Anti-Debug", true},
        {"AD_PATCH_V2", {0x66, 0xC1, 0xE8, 0x05, 0x00, 0xC3}, "Anti-Debug", true},
        {"AD_EXIT_BLOCK", {0xED, 0x31, 0xC0, 0x74, 0x01, 0xE8, 0x0F, 0xA2, 0x66, 0xC1, 0xE8, 0x05, 0x00, 0xC3}, "Anti-Debug (Exit)", true},
        {"AD_CRASH_V2", {0xCC, 0xED, 0x00}, "Anti-Debug (Crash)", true},
        {"AD_RDTSCP", {0x0F, 0x31, -1, -1, -1, -1, -1, 0x0F, 0xC7, 0xF8}, "Anti-Debug (RDTSCP)", true},

        // virt
        {"VM_DISPATCH_X64", {0x48, 0x89, 0xC3, 0x48, 0x31, 0xC8, 0x48, 0xC1, 0xEA, 0x08, 0x48, 0xC1, 0xE0, 0x04}, "Virtualization", true},
        {"VM_DISPATCH_X86", {0x89, 0xD8, 0x01, 0xC8, 0x29, 0xD3, 0xD3, 0xE1, 0x53, 0x5B, 0xD3, 0xE9, 0x09, 0xD0, 0x4A}, "Virtualization", true},
        {"BAD_JMP_X64", {0x0F, 0xA2, 0x48, 0x89, 0xC0, 0x48, 0x89, 0xDA, 0xFF, 0x25}, "Virtualization (Junk)", true},

        // watermark
        {"MARK_ENIGMA", {0x45, 0x6e, 0x69, 0x67, 0x6d, 0x61, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x6f, 0x72}, "Fake Sig", true},
        {"MARK_DENUVO", {0x64, 0x65, 0x6e, 0x75, 0x76, 0x6f, 0x5f, 0x61, 0x74, 0x64}, "Fake Sig", true},
        {"MARK_NUITKA", {0x4e, 0x55, 0x49, 0x54, 0x4b, 0x41, 0x5f, 0x4f, 0x4e, 0x45, 0x46, 0x49, 0x4c, 0x45}, "Fake Sig", true},
        {"RET_BY_VAR", {0x8B, 0x45, 0x08, 0x05, -1, -1, -1, -1, 0x8B, 0x00, 0x05, -1, -1, -1, -1, 0xC3}, "Internal Logic", true},
        {"HIDE_STRING_ENTRY", {0x31, 0xC0, 0x74, 0x01, 0xE8, 0x0F, 0xA2, -1, -1, -1, -1, -1, 0x0F, 0xA2, 0x48, 0x89, 0xC0}, "String Obf", true}
    };

    vector<string> fakeSections = {
        ".obfh", ".vmp0", ".vmp1", ".vmp2", "UPX0", ".enigma1", ".enigma2",
        ".winlice", ".petite", ".rlp", ".dsstext", "logicoma", "adr", "have",
        "30cm", "PETETRIS", ".alien", ".pwdprot", ".arch", ".vlizer", "__wibu00"
    };

    for (int i = 0; i < numSections; i++) {
        unsigned char* d = (unsigned char*)pBase + sections[i].PointerToRawData;
        size_t s = sections[i].SizeOfRawData;
        DWORD r = sections[i].VirtualAddress;
        DWORD o = sections[i].PointerToRawData;
        char sn[9] = { 0 }; memcpy(sn, sections[i].Name, 8); string name(sn);

        for (auto& fs : fakeSections) {
            if (name == fs) AddMatch(r, o, "Primary Marker", "Section: " + name, true);
        }

        // RWX Detection
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_READ) &&
            (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            AddMatch(r, o, "Anomaly", "RWX Section: " + name, true);
        }

        auto varRes = findPatterns(d, s, { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        for (auto pos : varRes) AddMatch(r + (DWORD)pos, o + (DWORD)pos, "Primary Marker", "Obfh Data Block (_0-_9)", true);

        for (auto& sig : sigs) {
            auto res = findPatterns(d, s, sig.pat);
            for (auto pos : res) AddMatch(r + (DWORD)pos, o + (DWORD)pos, sig.cat, sig.name, sig.strong);
        }

        // HIDE_STRING Detection 
        for (size_t j = 0; j + 4 < s; j++) {
            int ser = 0; size_t k = j;
            while (k + 4 <= s) {
                //  1: C6 45 YY XX (mov byte ptr [ebp/rbp+YY], XX)
                if (d[k] == 0xC6 && d[k + 1] == 0x45) { ser++; k += 4; }
                //  2: C6 44 24 YY XX (mov byte ptr [esp/rsp+YY], XX)
                else if (k + 5 <= s && d[k] == 0xC6 && d[k + 1] == 0x44 && d[k + 2] == 0x24) { ser++; k += 5; }
                //  3: B8 XX 00 00 00 88 45 YY (TCC style: mov eax, XX; mov [rbp+YY], al)
                else if (k + 8 <= s && d[k] == 0xB8 && d[k + 2] == 0x00 && d[k + 3] == 0x00 && d[k + 4] == 0x00 && d[k + 5] == 0x88 && d[k + 6] == 0x45) { ser++; k += 8; }
                //  4: B8 XX 00 00 00 88 85 YY YY YY YY (TCC style with large offset)
                else if (k + 11 <= s && d[k] == 0xB8 && d[k + 2] == 0x00 && d[k + 3] == 0x00 && d[k + 4] == 0x00 && d[k + 5] == 0x88 && d[k + 6] == 0x85) { ser++; k += 11; }
                else break;
            }
            if (ser >= 6) { // Minimum 6 bytes to reduce false positives, if you want you can change it to see more in HIDE_STRING
                AddMatch(r + (DWORD)j, o + (DWORD)j, "String Obf", "HIDE_STRING sequence (" + to_string(ser) + " chars)", true);
                j = k - 1;
            }
        }
    }

    if (!matches.empty()) {
        int strongHits = 0;
        for (auto& m : matches) if (m.isStrong) strongHits++;

        double density = (double)matches.size() / (fileSize / 1024.0);

        if (isTCC) {
            setColor(COLOR_MAGENTA); cout << "[+] Compiler: Tiny C (TCC)\n";
            setColor(COLOR_MAGENTA);    cout << " Language: C\n";
        }

        if (hasStrongIndicator) {
            setColor(COLOR_RED); cout << "[!] Obfus.h Protection: CONFIRMED\n";
        }
        else {
            setColor(COLOR_YELLOW); cout << "[?] Obfus.h Protection: SUSPECTED\n";
        }

        setColor(COLOR_CYAN);
        cout << " Detection Score:   " << fixed << setprecision(2) << (strongHits * 10.0 + matches.size()) << "\n";
        cout << " Marker Density:    " << density << " hits/KB\n";
        setColor(COLOR_DEFAULT);

        sort(matches.begin(), matches.end(), [](const Match& a, const Match& b) { return a.rva < b.rva; });
        cout << "\nDetailed Detection Log (" << matches.size() << " hits):\n";
        cout << left << setw(12) << "RVA" << setw(12) << "Offset" << setw(20) << "Category" << "Details" << endl;
        cout << string(70, '-') << endl;
        for (auto& m : matches) {
            if (m.isStrong) setColor(COLOR_RED);
            else setColor(COLOR_YELLOW);

            cout << "0x" << hex << uppercase << setw(8) << setfill('0') << m.rva << setfill(' ') << dec
                << "  0x" << hex << uppercase << setw(8) << setfill('0') << m.offset << setfill(' ') << dec
                << "  " << setw(18) << m.category << m.detail << endl;
            setColor(COLOR_DEFAULT);
        }
    }
    else {
        setColor(COLOR_GREEN); cout << "[+] No Obfus.h markers found.\n"; setColor(COLOR_DEFAULT); 
    }
    cout << "----------------------------------------------------\n";
    UnmapViewOfFile(pBase); CloseHandle(hMap); CloseHandle(hFile);
    return 0;
}
