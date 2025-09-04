#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <cstdint>

static const char* DEFAULT_STATE_DIR = "/etc/telegraf";
static const char* STATE_FILE = "state.ini";

struct State {
  std::string boot_id;
  uint64_t last_seq = 0;
};

struct Pattern {
  std::regex re;
  std::string subsystem;
  int dev_group;
};

struct Record {
  int pri = 6;
  uint64_t seq = 0;
  uint64_t ts = 0;
  std::string msg;
};

static std::string trim(const std::string& s);
static bool load_state(const std::string& path, State& st);
static bool read_file(const std::string& path, std::string& out);
static std::string read_boot_id();
static bool atomic_write_state(const std::string& path, const State& st);
static int open_kmsg();
static void build_patterns(std::vector<Pattern>& pats);
static std::string hostname_str();
static std::vector<std::string> split(const std::string& s, char sep);
static bool read_kmsg_record(int fd, Record& rec);

int main (int argc, char** argv) {
  std::string state_dir = DEFAULT_STATE_DIR;
  std::string measurement = "device_errors";
  for (int i=1;i<argc;i++) {
    std::string a = argv[i];
    if (a=="--state-dir" && i+1<argc) state_dir = argv[++i];
    else if (a=="--measurement" && i+1<argc) measurement = argv[++i];
  }

  ::mkdir(state_dir.c_str(), 0755);
  std::string state_path = state_dir + "/" + STATE_FILE;

  State st{};
  State loaded{};
  load_state(state_path, loaded);
  st.boot_id = read_boot_id();
  if (st.boot_id == loaded.boot_id) st.last_seq = loaded.last_seq;
  else st.last_seq = 0;

  atomic_write_state(state_path, st);

  int kfd = open_kmsg();
  if (kfd < 0) {
    std::cerr << "[telegraf-dmesg] cannot open /dev/kmsg (need root or proper caps)\n";
    return 1;
  }

  std::vector<Pattern> patterns;
  build_patterns(patterns);

  std::string host = hostname_str();
  struct pollfd pfd { kfd, POLLIN, 0 };

  while (true) {
    int pr = ::poll(&pfd, 1, -1);
    if (pr <= 0) continue;
    if (pfd.revents & POLLIN) {
      Record r;
      if (!read_kmsg_record(kfd, r)) continue;

      if (r.seq > st.last_seq) {
        st.last_seq = r.seq;
        atomic_write_state(state_path, st);
      }

      bool hit = false;
      std::string subsystem = "generic";
      std::string device = "unknown";
      for (auto& p : patterns) {
        std::smatch m;
        if (std::regex_search(r.msg, m, p.re)) {
          hit = true;
          subsystem = p.subsystem;
          if (p.dev_group >= 0 && p.dev_group < (int)m.size() && m[p.dev_group].matched) {
            device = m[p.dev_group].str();
          }
          break;
        }
      }
      if (!hit) continue;

      std::map<std::string,std::string> tags{
        {"host", host},
        {"device", device},
        {"subsystem", subsystem},
        {"source", "kmsg"}
      };
      std::map<std::string,std::string> fields{
        {"count", "1i"},
        {"pri", std::to_string(r.pri) + "i"},
        {"seq", std::to_string(r.seq) + "i"},
        {"msg", r.msg}
      };
//      emit_influx(measurement, tags, fields);
    }
  }

  return 0;
}

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \r\n\t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \r\n\t");
    return s.substr(b, e - b + 1);
}

static bool load_state(const std::string& path, State& st) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        auto p = line.find('=');
        if (p == std::string::npos) continue;
        std::string k = trim(line.substr(0, p));
        std::string v = trim(line.substr(p+1));
        if (k == "boot_id") st.boot_id = v;
        else if (k == "last_seq") st.last_seq = std::strtoull(v.c_str(), nullptr, 10);
    }
    return true;
}

static bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path);
    if (!f) return false;
    std::ostringstream ss; ss << f.rdbuf();
    out = ss.str();
    return true;
}

static std::string read_boot_id() {
    std::string s;
    if (read_file("/proc/sys/kernel/random/boot_id", s)) return trim(s);
    return "";
}

static bool atomic_write_state(const std::string& path, const State& st) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) return false;
        f << "boot_id=" << st.boot_id << "\n";
        f << "last_seq=" << st.last_seq << "\n";
        f.flush();
        if (!f) return false;
        int fd = ::open(tmp.c_str(), O_RDONLY);
        if (fd >= 0) { ::fsync(fd); ::close(fd); }
    }
    return ::rename(tmp.c_str(), path.c_str()) == 0;
}

static int open_kmsg() {
    return ::open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
}

static void build_patterns(std::vector<Pattern>& pats) {
    using std::regex; using std::regex_constants::icase;
    pats.push_back({regex(R"(EXT4-fs (?:\(([^)]+)\): )?(?:error|errors|BUG|warn).*)", icase), "ext4", 1});
    pats.push_back({regex(R"(XFS \(([^)]+)\): (?:Metadata corruption|Internal error|Corruption detected).*)", icase), "xfs", 1});
    pats.push_back({regex(R"(BTRFS (?:error|warning): .*)", icase), "btrfs", -1});
    pats.push_back({regex(R"(blk_update_request: I/O error, dev ([^, ]+).*)", icase), "block", 1});
    pats.push_back({regex(R"(Buffer I/O error on dev ([^, ]+).*)", icase), "block", 1});
    pats.push_back({regex(R"(end_request: I/O error, dev ([^, ]+).*)", icase), "block", 1});
    pats.push_back({regex(R"(nvme[^:]*: I/O .* timeout.*)", icase), "nvme", -1});
    pats.push_back({regex(R"(nvme[^:]*: resetting controller.*)", icase), "nvme", -1});
    pats.push_back({regex(R"(scsi [0-9:]+: .*(?:rejecting I/O|frozen|offline|reset).*)", icase), "scsi", -1});
}

static std::string hostname_str() {
    char buf[256];
    if (::gethostname(buf, sizeof(buf)) == 0) {
        buf[sizeof(buf)-1] = 0;
        return std::string(buf);
    }
    return "unknown";
}

static std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t pos = s.find(sep, start);
        if (pos == std::string::npos) { out.push_back(s.substr(start)); break; }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

static bool read_kmsg_record(int fd, Record& rec) {
    char buf[8192];
    ssize_t n = ::read(fd, buf, sizeof(buf)-1);
    if (n <= 0) return false;
    buf[n] = 0;
    std::string line(buf);
    auto semi = line.find(';');
    if (semi == std::string::npos) return false;
    std::string header = line.substr(0, semi);
    rec.msg = trim(line.substr(semi+1));
    auto parts = split(header, ',');
    if (parts.size() >= 3) {
        rec.pri = std::atoi(parts[0].c_str());
        rec.seq = std::strtoull(parts[1].c_str(), nullptr, 10);
        rec.ts  = std::strtoull(parts[2].c_str(), nullptr, 10);
    }
    return true;
}

