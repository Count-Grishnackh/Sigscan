#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <coroutine>
#include <expected>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <print>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace sigscan::inline v1 {

    template<typename T>
    concept ByteType = std::same_as<T, std::uint8_t> ||
        std::same_as<T, char> ||
        std::same_as<T, unsigned char>;

    template<typename T>
    concept ContainerType = requires(T t) {
        t.data();
        t.size();
        typename T::value_type;
            requires ByteType<typename T::value_type>;
    };

    template<typename T>
    concept AddressType = std::integral<T> && sizeof(T) >= sizeof(void*);

    static_assert(std::endian::native == std::endian::little,
        "This library requires little-endian architecture");

    enum class [[nodiscard]] ScanError : std::uint8_t {
        InvalidPattern = 1,
        InvalidMemoryRegion,
        PatternNotFound,
        AccessViolation,
        InsufficientPermissions,
        ProcessNotFound,
        CoroutineError
    };

    [[nodiscard]] consteval std::string_view error_message(ScanError error) noexcept {
        using enum ScanError;
        switch (error) {
        case InvalidPattern: return "Invalid pattern format";
        case InvalidMemoryRegion: return "Invalid memory region";
        case PatternNotFound: return "Pattern not found";
        case AccessViolation: return "Memory access violation";
        case InsufficientPermissions: return "Insufficient permissions";
        case ProcessNotFound: return "Process not found";
        case CoroutineError: return "Coroutine execution error";
        }
        std::unreachable();
    }

    template<typename T>
    using ScanResult = std::expected<T, ScanError>;
    class ProcessHandle {
    private:
        struct HandleDeleter {
            void operator()(HANDLE h) const noexcept {
                if (h && h != INVALID_HANDLE_VALUE) {
                    CloseHandle(h);
                }
            }
        };

        std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter> handle_;

    public:
        explicit ProcessHandle(HANDLE h) noexcept : handle_(h) {}

        ProcessHandle(const ProcessHandle&) = delete;
        ProcessHandle& operator=(const ProcessHandle&) = delete;

        ProcessHandle(ProcessHandle&&) = default;
        ProcessHandle& operator=(ProcessHandle&&) = default;

        [[nodiscard]] HANDLE get() const noexcept { return handle_.get(); }
        [[nodiscard]] explicit operator bool() const noexcept {
            return handle_ && handle_.get() != INVALID_HANDLE_VALUE;
        }
    };
    class PatternByte {
    private:
        std::optional<std::uint8_t> value_;

    public:
        constexpr PatternByte() noexcept = default;
        constexpr explicit PatternByte(std::uint8_t byte) noexcept : value_(byte) {}

        template<typename Self>
        [[nodiscard]] constexpr bool is_wildcard(this Self&& self) noexcept {
            return !self.value_.has_value();
        }

        template<typename Self>
        [[nodiscard]] constexpr std::uint8_t value(this Self&& self) noexcept {
            return self.value_.value_or(0);
        }

        [[nodiscard]] constexpr bool matches(std::uint8_t byte) const noexcept {
            return is_wildcard() || value_ == byte;
        }

        [[nodiscard]] constexpr auto operator<=>(const PatternByte&) const noexcept = default;

        friend constexpr PatternByte operator|(PatternByte a, PatternByte b) noexcept {
            return a.is_wildcard() ? b : a;
        }
    };

    class PatternFactory {
    public:
        // Fixed: Removed constexpr since from_ida_string is not constexpr
        [[nodiscard]] auto operator()(std::string_view pattern) const {
            return from_ida_string(pattern);
        }

        [[nodiscard]] static ScanResult<std::vector<PatternByte>> from_ida_string(std::string_view pattern) {
            std::vector<PatternByte> result;

            // Совместимая с MSVC версия
            auto tokens = pattern | std::views::split(' ');
            for (auto&& token : tokens) {
                if (std::ranges::empty(token)) continue;

                std::string token_str{ token.begin(), token.end() };

                if (token_str == "?") {
                    result.emplace_back();
                }
                else if (token_str.length() == 2 &&
                    std::ranges::all_of(token_str, [](char c) { return std::isxdigit(c); })) {
                    auto byte_val = static_cast<std::uint8_t>(std::stoul(token_str, nullptr, 16));
                    result.emplace_back(byte_val);
                }
                else {
                    return std::unexpected(ScanError::InvalidPattern);
                }
            }

            return result;
        }

        template<ContainerType auto& bytes>
        [[nodiscard]] static consteval auto from_bytes_constexpr() {
            std::array<PatternByte, bytes.size()> result{};
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                result[i] = PatternByte{ static_cast<std::uint8_t>(bytes[i]) };
            }
            return result;
        }

        template<ContainerType Container>
        [[nodiscard]] static std::vector<PatternByte> from_bytes(const Container& bytes) {
            std::vector<PatternByte> result;
            result.reserve(bytes.size());
            for (auto byte : bytes) {
                result.emplace_back(static_cast<std::uint8_t>(byte));
            }
            return result;
        }
    };

    struct MemoryRegion {
        std::uintptr_t base_address;
        std::size_t size;
        DWORD protection;

        [[nodiscard]] constexpr std::uintptr_t end_address() const noexcept {
            return base_address + size;
        }

        [[nodiscard]] constexpr bool contains(std::uintptr_t address) const noexcept {
            return address >= base_address && address < end_address();
        }

        [[nodiscard]] constexpr bool is_readable() const noexcept {
            constexpr DWORD readable_flags = PAGE_READONLY | PAGE_READWRITE |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE;
            return (protection & readable_flags) != 0;
        }

        [[nodiscard]] constexpr bool contains(std::uintptr_t start, std::size_t length) const noexcept {
            return contains(start) && contains(start + length - 1);
        }
    };

    class SearchStrategy {
    public:
        virtual ~SearchStrategy() = default;

        [[nodiscard]] virtual ScanResult<std::vector<std::uintptr_t>>
            search(std::span<const std::uint8_t> memory,
                std::span<const PatternByte> pattern,
                std::uintptr_t base_address) const = 0;

        [[nodiscard]] virtual std::optional<std::string_view> name() const noexcept {
            return std::nullopt;
        }
    };

    class NaiveSearchStrategy final : public SearchStrategy {
    public:
        [[nodiscard]] ScanResult<std::vector<std::uintptr_t>>
            search(std::span<const std::uint8_t> memory,
                std::span<const PatternByte> pattern,
                std::uintptr_t base_address) const override {

            std::vector<std::uintptr_t> results;

            if (pattern.empty() || memory.size() < pattern.size()) {
                return results;
            }

            // Fixed: Replaced [[assume]] with debug assertion that compiles to nothing in release
#ifdef _DEBUG
            assert(pattern.size() > 0);
            assert(memory.size() >= pattern.size());
#endif

            for (std::size_t i = 0; i <= memory.size() - pattern.size(); ++i) {
                if (std::ranges::equal(
                    memory.subspan(i, pattern.size()),
                    pattern,
                    [](std::uint8_t byte, const PatternByte& pat) {
                        return pat.matches(byte);
                    })) {
                    results.push_back(base_address + i);
                }
            }

            return results;
        }

        [[nodiscard]] std::optional<std::string_view> name() const noexcept override {
            return "Naive";
        }
    };

    class BoyerMooreSearchStrategy final : public SearchStrategy {
    private:
        [[nodiscard]] static std::array<std::size_t, 256> build_bad_char_table(
            std::span<const PatternByte> pattern) {

            std::array<std::size_t, 256> table;
            table.fill(pattern.size());

            for (std::size_t i = 0; i < pattern.size() - 1; ++i) {
                if (!pattern[i].is_wildcard()) {
                    table[pattern[i].value()] = pattern.size() - 1 - i;
                }
            }

            return table;
        }

    public:
        [[nodiscard]] ScanResult<std::vector<std::uintptr_t>>
            search(std::span<const std::uint8_t> memory,
                std::span<const PatternByte> pattern,
                std::uintptr_t base_address) const override {

            std::vector<std::uintptr_t> results;

            if (pattern.empty() || memory.size() < pattern.size()) {
                return results;
            }

            const auto bad_char_table = build_bad_char_table(pattern);
            std::size_t shift = 0;

            while (shift <= memory.size() - pattern.size()) {
                std::size_t j = pattern.size() - 1;

                while (j < pattern.size() && pattern[j].matches(memory[shift + j])) {
                    if (j == 0) break;
                    --j;
                }

                if (j == 0 && pattern[0].matches(memory[shift])) {
                    results.push_back(base_address + shift);
                    shift += 1;
                }
                else {
                    shift += (std::max)(static_cast<std::size_t>(1),
                        bad_char_table[memory[shift + j]]);
                }
            }

            return results;
        }

        [[nodiscard]] std::optional<std::string_view> name() const noexcept override {
            return "Boyer-Moore";
        }
    };
    class SIMDSearchStrategy final : public SearchStrategy {
    public:
        [[nodiscard]] ScanResult<std::vector<std::uintptr_t>>
            search(std::span<const std::uint8_t> memory,
                std::span<const PatternByte> pattern,
                std::uintptr_t base_address) const override {

            bool has_wildcards = false;
            for (const auto& byte : pattern) {
                if (byte.is_wildcard()) {
                    has_wildcards = true;
                    break;
                }
            }

            if (has_wildcards) {
                return BoyerMooreSearchStrategy{}.search(memory, pattern, base_address);
            }

            return NaiveSearchStrategy{}.search(memory, pattern, base_address);
        }

        [[nodiscard]] std::optional<std::string_view> name() const noexcept override {
            return "SIMD-Optimized";
        }
    };

    struct ScanConfig {
        bool scan_executable_only = true;
        bool scan_writable_only = false;
        std::size_t max_results = (std::numeric_limits<std::size_t>::max)();
        std::unique_ptr<SearchStrategy> strategy;

        explicit ScanConfig(std::unique_ptr<SearchStrategy> strat = std::make_unique<BoyerMooreSearchStrategy>())
            : strategy(std::move(strat)) {
        }

        ScanConfig(const ScanConfig& other)
            : scan_executable_only(other.scan_executable_only)
            , scan_writable_only(other.scan_writable_only)
            , max_results(other.max_results)
            , strategy(std::make_unique<BoyerMooreSearchStrategy>()) {
        }

        ScanConfig& operator=(const ScanConfig& other) {
            if (this != &other) {
                scan_executable_only = other.scan_executable_only;
                scan_writable_only = other.scan_writable_only;
                max_results = other.max_results;
                strategy = std::make_unique<BoyerMooreSearchStrategy>();
            }
            return *this;
        }

        ScanConfig(ScanConfig&&) = default;
        ScanConfig& operator=(ScanConfig&&) = default;
    };

    class SignatureScanner {
    private:
        ProcessHandle process_handle_;

        [[nodiscard]] ScanResult<std::vector<MemoryRegion>> enumerate_memory_regions() const {
            std::vector<MemoryRegion> regions;
            std::uintptr_t address = 0;
            MEMORY_BASIC_INFORMATION mbi{};

            while (VirtualQueryEx(process_handle_.get(),
                reinterpret_cast<LPCVOID>(address),
                &mbi, sizeof(mbi))) {

                if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
                    regions.emplace_back(MemoryRegion{
                        .base_address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress),
                        .size = mbi.RegionSize,
                        .protection = mbi.Protect
                        });
                }

                address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (address == 0) break;
            }

            return regions;
        }

        [[nodiscard]] ScanResult<std::vector<std::uint8_t>> read_memory(const MemoryRegion& region) const {
            std::vector<std::uint8_t> buffer(region.size);
            SIZE_T bytes_read = 0;

            if (!ReadProcessMemory(process_handle_.get(),
                reinterpret_cast<LPCVOID>(region.base_address),
                buffer.data(),
                buffer.size(),
                &bytes_read)) {
                return std::unexpected(ScanError::AccessViolation);
            }

            buffer.resize(bytes_read);
            return buffer;
        }

    public:
        explicit SignatureScanner(DWORD process_id)
            : process_handle_(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id)) {

            if (!process_handle_) {
                throw std::runtime_error(std::format("Failed to open process with ID: {}", process_id));
            }
        }

        struct ScanTask {
            struct promise_type {
                ScanResult<std::vector<std::uintptr_t>> result;

                ScanTask get_return_object() {
                    return ScanTask{ std::coroutine_handle<promise_type>::from_promise(*this) };
                }
                std::suspend_never initial_suspend() noexcept { return {}; }
                std::suspend_always final_suspend() noexcept { return {}; }
                void unhandled_exception() {
                    result = std::unexpected(ScanError::CoroutineError);
                }
                void return_value(ScanResult<std::vector<std::uintptr_t>> value) {
                    result = std::move(value);
                }
            };

            std::coroutine_handle<promise_type> handle;

            ScanTask(std::coroutine_handle<promise_type> h) : handle(h) {}
            ~ScanTask() { if (handle) handle.destroy(); }

            ScanTask(const ScanTask&) = delete;
            ScanTask& operator=(const ScanTask&) = delete;

            ScanTask(ScanTask&& other) noexcept : handle(std::exchange(other.handle, {})) {}
            ScanTask& operator=(ScanTask&& other) noexcept {
                if (this != &other) {
                    if (handle) handle.destroy();
                    handle = std::exchange(other.handle, {});
                }
                return *this;
            }

            bool await_ready() const noexcept { return handle.done(); }
            void await_suspend(std::coroutine_handle<>) const noexcept {}
            ScanResult<std::vector<std::uintptr_t>> await_resume() const {
                return std::move(handle.promise().result);
            }
        };

        [[nodiscard]] ScanTask scan_async(std::span<const PatternByte> pattern,
            const ScanConfig& config = ScanConfig{}) {
            auto regions_result = enumerate_memory_regions();
            if (!regions_result) {
                co_return std::unexpected(regions_result.error());
            }

            std::vector<std::uintptr_t> all_results;

            for (const auto& region : *regions_result) {
                if (!region.is_readable()) continue;

                if (config.scan_executable_only &&
                    !(region.protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                    continue;
                }

                if (config.scan_writable_only &&
                    !(region.protection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                    continue;
                }

                auto memory_result = read_memory(region);
                if (!memory_result) continue;

                auto search_result = config.strategy->search(*memory_result, pattern, region.base_address);
                if (search_result && !search_result->empty()) {
                    std::ranges::copy(*search_result, std::back_inserter(all_results));

                    if (all_results.size() >= config.max_results) {
                        all_results.resize(config.max_results);
                        break;
                    }
                }
            }

            co_return all_results;
        }

        [[nodiscard]] ScanResult<std::vector<std::uintptr_t>> scan(
            std::span<const PatternByte> pattern,
            const ScanConfig& config = ScanConfig{}) {

            auto task = scan_async(pattern, config);
            while (!task.await_ready()) {
                std::this_thread::yield();
            }
            return task.await_resume();
        }

        [[nodiscard]] ScanResult<std::vector<std::uintptr_t>> scan_ida_pattern(
            std::string_view pattern,
            const ScanConfig& config = ScanConfig{}) {

            auto pattern_result = PatternFactory::from_ida_string(pattern);
            if (!pattern_result) {
                return std::unexpected(pattern_result.error());
            }
            return scan(*pattern_result, config);
        }

        template<ContainerType Container>
        [[nodiscard]] ScanResult<std::vector<std::uintptr_t>> scan_bytes(
            const Container& bytes,
            const ScanConfig& config = ScanConfig{}) {

            auto pattern = PatternFactory::from_bytes(bytes);
            return scan(pattern, config);
        }

        [[nodiscard]] ScanResult<std::optional<std::uintptr_t>> find_first(
            std::span<const PatternByte> pattern,
            const ScanConfig& config = ScanConfig{}) {

            auto modified_config = config;
            modified_config.max_results = 1;

            return scan(pattern, modified_config).transform([](auto&& results) {
                return results.empty() ? std::nullopt : std::optional{ results.front() };
                });
        }

        template<typename F>
        auto operator|(F&& func) -> decltype(func(*this)) {
            return func(*this);
        }
    };

    class ScanConfigBuilder {
    private:
        ScanConfig config_;

    public:
        ScanConfigBuilder& executable_only(bool value = true)& {
            config_.scan_executable_only = value;
            return *this;
        }

        ScanConfigBuilder&& executable_only(bool value = true)&& {
            config_.scan_executable_only = value;
            return std::move(*this);
        }

        ScanConfigBuilder& writable_only(bool value = true)& {
            config_.scan_writable_only = value;
            return *this;
        }

        ScanConfigBuilder&& writable_only(bool value = true)&& {
            config_.scan_writable_only = value;
            return std::move(*this);
        }

        ScanConfigBuilder& max_results(std::size_t count)& {
            config_.max_results = count;
            return *this;
        }

        ScanConfigBuilder&& max_results(std::size_t count)&& {
            config_.max_results = count;
            return std::move(*this);
        }

        template<std::derived_from<SearchStrategy> Strategy, typename... Args>
        ScanConfigBuilder& strategy(Args&&... args)& {
            config_.strategy = std::make_unique<Strategy>(std::forward<Args>(args)...);
            return *this;
        }

        template<std::derived_from<SearchStrategy> Strategy, typename... Args>
        ScanConfigBuilder&& strategy(Args&&... args)&& {
            config_.strategy = std::make_unique<Strategy>(std::forward<Args>(args)...);
            return std::move(*this);
        }

        [[nodiscard]] ScanConfig build()&& {
            return std::move(config_);
        }
    };

    namespace utils {
        template<std::size_t N>
        consteval bool validate_pattern(const char(&pattern)[N]) {
            return N > 0;
        }

        consteval auto operator""_pattern(const char* str, std::size_t len) {
            return std::string_view{ str, len };
        }

        [[nodiscard]] inline auto make_scanner(DWORD pid) {
            return std::make_unique<SignatureScanner>(pid);
        }

        [[nodiscard]] inline auto current_process_scanner() {
            return make_scanner(GetCurrentProcessId());
        }

        template<typename... Args>
        void print_results(const ScanResult<std::vector<std::uintptr_t>>& results,
            std::format_string<Args...> fmt, Args&&... args) {
            if (results) {
                std::println("{}:", std::format(fmt, std::forward<Args>(args)...));
                for (const auto& addr : *results) {
                    std::println("  0x{:X}", addr);
                }
            }
            else {
                std::println("Scan failed: {}", error_message(results.error()));
            }
        }
    }

    namespace ranges {
        template<typename Range>
        auto in_range(std::uintptr_t start, std::uintptr_t end) {
            return [start, end](Range&& range) {
                std::vector<std::uintptr_t> result;
                for (auto addr : range) {
                    if (addr >= start && addr <= end) {
                        result.push_back(addr);
                    }
                }
                return result;
                };
        }

        template<typename Range>
        auto take_first(std::size_t n) {
            return [n](Range&& range) {
                std::vector<std::uintptr_t> result;
                std::size_t count = 0;
                for (auto addr : range) {
                    if (count >= n) break;
                    result.push_back(addr);
                    ++count;
                }
                return result;
                };
        }

        template<typename Range>
        auto sorted() {
            return [](Range&& range) {
                std::vector<std::uintptr_t> result(range.begin(), range.end());
                std::ranges::sort(result);
                return result;
                };
        }
    }

}