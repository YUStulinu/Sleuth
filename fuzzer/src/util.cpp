#include "util.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace fs = std::filesystem;

namespace sleuth {

bool read_file(const std::string& path, Bytes& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

bool write_file(const std::string& path, const Bytes& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write((const char*)data.data(), (std::streamsize)data.size());
    return (bool)f;
}

bool write_text(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << text;
    return (bool)f;
}

bool write_atomic(const std::string& path, const std::string& text) {
    std::string tmp = path + ".tmp";
    if (!write_text(tmp, text)) return false;
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        // Windows: the target may be open by a reader for a moment; fall back to a copy.
        fs::copy_file(tmp, path, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmp, ec);
    }
    return !ec;
}

bool make_dirs(const std::string& path) {
    std::error_code ec;
    fs::create_directories(path, ec);
    return fs::is_directory(path, ec);
}

std::vector<std::string> list_files(const std::string& dir) {
    std::vector<std::string> out;
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
        if (it->is_regular_file(ec)) out.push_back(it->path().string());
    std::sort(out.begin(), out.end());
    return out;
}

bool file_exists(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec);
}

std::string join(const std::string& a, const std::string& b) { return (fs::path(a) / b).string(); }

std::string basename(const std::string& path) { return fs::path(path).filename().string(); }

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

std::string hex64(uint64_t v) {
    char buf[17];
    std::snprintf(buf, sizeof buf, "%016llx", (unsigned long long)v);
    return buf;
}

}  // namespace sleuth
