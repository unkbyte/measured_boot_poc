// Yes i know its stupid but i was to lazy to set up the compiler correctly to declare this Macro directly ;D
#define NTDDI_VERSION NTDDI_WIN11_GA

#include <windows.h>
#include <tbs.h>
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <map>
#include <expected>
#include <wintrust.h>
#include <imagehlp.h>
#include <wincrypt.h>
#include <mscat.h>

enum class errors {
    tbsi_get_device_info_failed,
    tbsi_get_tcg_log_ex_size_failed,
    tbsi_get_tcg_log_ex_data_fetch_failed,
    file_open_failed,
    crypt_cat_admin_acquire_context2_failed,
    crypt_cat_admin_calc_hash_from_file_handle_failed,
    log_too_small,
    invalid_digest_length,
    event_data_size_exceeds_bounds,
    buffer_underflow,
    invalid_digest_algorithm
};

const char* tcg_error_to_string(const errors err) {
    switch (err) {
        case errors::tbsi_get_device_info_failed:
            return "tbsi_get_device_info failed";
        case errors::tbsi_get_tcg_log_ex_size_failed:
            return "tbsi_get_tcg_log_ex (size query) failed";
        case errors::tbsi_get_tcg_log_ex_data_fetch_failed:
            return "tbsi_get_tcg_log_ex (data fetch) failed";
        case errors::file_open_failed:
            return "failed to open file";
        case errors::crypt_cat_admin_acquire_context2_failed:
            return "crypt_cat_admin_acquire_context2 failed";
        case errors::crypt_cat_admin_calc_hash_from_file_handle_failed:
            return "crypt_cat_admin_calc_hash_from_file_handle failed";
        case errors::log_too_small:
            return "log too small for tpm 2.0 event records";
        case errors::invalid_digest_length:
            return "invalid digest length";
        case errors::event_data_size_exceeds_bounds:
            return "event data size exceeds bounds";
        default:
            return "unknown error";
    }
}

enum class tbs_tcg_log : std::uint32_t {
    srtm_current = 0,
    drtm_current,
    srtm_boot,
    srtm_resume
};

constexpr std::uint32_t ev_efi_boot_services_application = 0x80000003;
constexpr std::uint32_t ev_efi_boot_services_driver = 0x80000004;
constexpr std::uint32_t ev_efi_runtime_services_driver = 0x80000005;

std::map<std::uint16_t, std::size_t> digest_sizes = {
    {0x0004, 20}, // TPM_ALG_SHA1
    {0x000B, 32}, // TPM_ALG_SHA256
    {0x000C, 48}, // TPM_ALG_SHA384
    {0x000D, 64}  // TPM_ALG_SHA512
};

#pragma pack(push, 1)
struct tcg_digest2 {
    uint16_t algorithm_id;
    // Followed by the digest bytes (variable length, determined by digest_sizes[algorithm_id]).
};

struct tcg_pcr_event2 {
    uint32_t pcr_index;
    uint32_t event_type;
    uint32_t digest_count;
    // Followed by:
    //   - An array of tcg_digest2 entries (each followed by its digest bytes)
    //   - A uint32_t event_size
    //   - Event data (variable length)
};
#pragma pack(pop)

std::string hex_encode(const std::uint8_t* data, std::size_t len) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::expected<TPM_DEVICE_INFO, errors> get_device_info() {
    TPM_DEVICE_INFO device_info = {};
    constexpr std::uint32_t info_size = sizeof(device_info);
    if (const std::uint32_t result = Tbsi_GetDeviceInfo(info_size, reinterpret_cast<PTPM_DEVICE_INFO>(&device_info)); result != TBS_SUCCESS)
        return std::unexpected(errors::tbsi_get_device_info_failed);
    return device_info;
}

std::expected<std::vector<std::uint8_t>, errors> get_tcg_log(tbs_tcg_log log_type) {
    std::uint32_t size = 0;
    std::uint32_t result = Tbsi_Get_TCG_Log_Ex(static_cast<std::uint32_t>(log_type), nullptr, &size);
    if (result != TBS_SUCCESS)
        return std::unexpected(errors::tbsi_get_tcg_log_ex_size_failed);
    std::vector<std::uint8_t> buffer(size);
    result = Tbsi_Get_TCG_Log_Ex(static_cast<std::uint32_t>(log_type), buffer.data(), &size);
    if (result != TBS_SUCCESS)
        return std::unexpected(errors::tbsi_get_tcg_log_ex_data_fetch_failed);
    buffer.resize(size);
    return buffer;
}

std::expected<std::string, errors> compute_authenticode_hash(const std::wstring& file_path) {
    HANDLE file_handle = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE)
        return std::unexpected(errors::file_open_failed);
    HCATADMIN cat_admin = nullptr;
    std::uint8_t hash[64] = {};
    auto hash_len = static_cast<std::uint32_t>(sizeof(hash));
    if (!CryptCATAdminAcquireContext2(&cat_admin, nullptr, BCRYPT_SHA256_ALGORITHM, 0, 0)) {
        CloseHandle(file_handle);
        return std::unexpected(errors::crypt_cat_admin_acquire_context2_failed);
    }
    if (!CryptCATAdminCalcHashFromFileHandle(file_handle, reinterpret_cast<DWORD*>(&hash_len), hash, 0)) {
        CryptCATAdminReleaseContext(cat_admin, 0);
        CloseHandle(file_handle);
        return std::unexpected(errors::crypt_cat_admin_calc_hash_from_file_handle_failed);
    }
    CryptCATAdminReleaseContext(cat_admin, 0);
    CloseHandle(file_handle);
    return hex_encode(hash, hash_len);
}

std::expected<const std::uint8_t*, errors> advance_ptr(const std::uint8_t*& ptr, std::size_t& remaining, std::size_t size) {
    if (remaining < size)
        return std::unexpected(errors::buffer_underflow);
    const std::uint8_t* old_ptr = ptr;
    ptr += size;
    remaining -= size;
    return old_ptr;
}

std::expected<void, errors> parse_tpm_event_log(const std::vector<std::uint8_t>& log_data) {
    const std::uint8_t* ptr = log_data.data();
    std::size_t remaining = log_data.size();

    auto trusted_hash_exp = compute_authenticode_hash(LR"(C:\Windows\Boot\EFI\bootmgfw.efi)");
    if (!trusted_hash_exp)
        return std::unexpected(trusted_hash_exp.error());
    const auto& trusted_hash = trusted_hash_exp.value();
    bool tampered_boot = false;

    while (remaining > sizeof(tcg_pcr_event2)) {
        auto header_ptr = advance_ptr(ptr, remaining, sizeof(tcg_pcr_event2));
        if (!header_ptr)
            return std::unexpected(header_ptr.error());

        const auto* event2 = reinterpret_cast<const tcg_pcr_event2*>(*header_ptr);
        std::vector<std::string> digests;

        for (std::uint32_t i = 0; i < event2->digest_count; ++i) {
            auto digest_header_ptr = advance_ptr(ptr, remaining, sizeof(tcg_digest2));
            if (!digest_header_ptr)
                return std::unexpected(digest_header_ptr.error());

            const auto* digest_header = reinterpret_cast<const tcg_digest2*>(*digest_header_ptr);
            auto digest_size = digest_sizes.contains(digest_header->algorithm_id) ? digest_sizes[digest_header->algorithm_id] : 0;

            if (digest_size == 0)
                return std::unexpected(errors::invalid_digest_algorithm);

            auto digest_ptr = advance_ptr(ptr, remaining, digest_size);
            if (!digest_ptr)
                return std::unexpected(digest_ptr.error());

            digests.push_back(hex_encode(*digest_ptr, digest_size));
        }

        auto event_size_ptr = advance_ptr(ptr, remaining, sizeof(std::uint32_t));
        if (!event_size_ptr)
            return std::unexpected(event_size_ptr.error());

        std::uint32_t event_size = *reinterpret_cast<const std::uint32_t*>(*event_size_ptr);

        auto event_data_ptr = advance_ptr(ptr, remaining, event_size);
        if (!event_data_ptr)
            return std::unexpected(event_data_ptr.error());

        if (event2->event_type == ev_efi_boot_services_application ||
            event2->event_type == ev_efi_boot_services_driver ||
            event2->event_type == ev_efi_runtime_services_driver) {

            std::println("\n-- Event Type: 0x{:x} --", event2->event_type);
            std::println("PCR: {}", event2->pcr_index);

            for (std::size_t i = 0; i < digests.size(); ++i) {
                if (i == 0 && trusted_hash.find(digests[i]) == std::string::npos)
                    tampered_boot = true;
                std::println("Digest [{}]: {}", i, digests[i]);
            }

            std::string event_data(reinterpret_cast<const char*>(*event_data_ptr), event_size);
            std::println("Event Size: {}", event_size);
            std::println("Event Data: {}", event_data);
        }
    }

    if (tampered_boot)
        std::println("Uh-oh, your boot chain has been tampered with!");

    return {};
}

int main() {
    auto device_info_exp = get_device_info();
    if (!device_info_exp) {
        std::println("Error: {}", tcg_error_to_string(device_info_exp.error()));
        return -1;
    }
    const TPM_DEVICE_INFO device_info = device_info_exp.value();
    std::println("TPM Version: {}", static_cast<int>(device_info.tpmVersion));

    if (device_info.tpmVersion != 2) {
        std::println("Error: Only TPM2 is supported!");
        return -1;
    }

    auto tcg_log_exp = get_tcg_log(tbs_tcg_log::srtm_current);
    if (!tcg_log_exp) {
        std::println("Error: {}", tcg_error_to_string(tcg_log_exp.error()));
        return -1;
    }
    const auto& tcg_log = tcg_log_exp.value();
    std::println("Fetched {} bytes", tcg_log.size());

    auto parse_exp = parse_tpm_event_log(tcg_log);
    if (!parse_exp) {
        std::println("Error: {}", tcg_error_to_string(parse_exp.error()));
        return -1;
    }
    return 0;
}