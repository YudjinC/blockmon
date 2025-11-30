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

// Prometheus client
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <mutex>
#include <atomic>
#include <csignal>
#include <memory>
#include <cerrno>

namespace pm = prometheus;
//

static const char* DEFAULT_STATE_DIR = "/var/lib/blockmon_exporter";
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

static std::string getenv_or(const char* name, const char* def);
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

// Prometheus objs
struct MetricKey {
  std::string subsystem;
  std::string device;

  bool operator<(const MetricKey& o) const {
    if (subsystem < o.subsystem) return true;
    if (subsystem > o.subsystem) return false;
    return device < o.device;
  }
};

static std::mutex g_metrics_mu;
static pm::Family<pm::Counter>* g_errors_family = nullptr;
static pm::Family<pm::Gauge>*   g_last_seq_family = nullptr;
static pm::Gauge* g_last_seq_gauge = nullptr;
static std::map<MetricKey, pm::Counter*> g_errors_by_dev;
static std::atomic<bool> g_stop{false};

static pm::Counter* get_error_counter(const std::string& host, const std::string& subsystem, const std::string& device);
static void sig_handler(int);
//

int main () {
  std::string state_dir = getenv_or("DMESG_EXPORTER_STATE_DIR", DEFAULT_STATE_DIR);
  std::string listen_addr = getenv_or("DMESG_EXPORTER_LISTEN_ADDR", "0.0.0.0:9105");
  log_info("state_dir=" + state_dir + ", state_path=" + state_path +
         ", listen_addr=" + listen_addr);

  ::mkdir(state_dir.c_str(), 0755);
  std::string state_path = state_dir + "/" + STATE_FILE;

  State st{};
  State loaded{};
  if (!load_state(state_path, loaded)) {
      log_info("no state file, starting from scratch: " + state_path);
  } else {
      log_info("loaded state: boot_id=" + loaded.boot_id +
               ", last_seq=" + std::to_string(loaded.last_seq));
  }
  st.boot_id = read_boot_id();
  if (st.boot_id.empty()) {
      log_warn("failed to read boot_id, state tracking may be broken");
  }
  if (st.boot_id == loaded.boot_id) {
      st.last_seq = loaded.last_seq;
      log_info("boot_id matches, resuming from seq=" + std::to_string(st.last_seq));
  } else {
      log_info("detected new boot_id: was=" + loaded.boot_id +
               ", now=" + st.boot_id + ", resetting last_seq to 0");
      st.last_seq = 0;
  }

  if (!atomic_write_state(state_path, st)) {
      log_error("failed to write state file: " + state_path + " : " + last_errno_string());
  }

  int kfd = open_kmsg();
  if (kfd < 0) {
    log_error("cannot open /dev/kmsg: " + last_errno_string() +
              " (need root or CAP_SYSLOG/CAP_SYS_ADMIN)")
    return 1;
  }
  log_info("opened /dev/kmsg successfully");

  std::vector<Pattern> patterns;
  build_patterns(patterns);

  std::string host = hostname_str();
  struct pollfd pfd { kfd, POLLIN, 0 };

  // Prometheus init
  pm::Exposer exposer{listen_addr};
  auto registry = std::make_shared<pm::Registry>();

  auto& errors_family = pm::BuildCounter()
      .Name("block_device_errors_total")
      .Help("Total number of device-related error messages from /dev/kmsg")
      .Register(*registry);

  auto& last_seq_family = pm::BuildGauge()
      .Name("block_kmsg_last_seq")
      .Help("Last processed /dev/kmsg sequence number")
      .Register(*registry);

  g_errors_family   = &errors_family;
  g_last_seq_family = &last_seq_family;

  auto& ls = last_seq_family.Add({{"host", host}});
  g_last_seq_gauge = &ls;
  g_last_seq_gauge->Set(static_cast<double>(st.last_seq));

  exposer.RegisterCollectable(registry);
  log_info("prometheus exposer initialized on " + listen_addr +
         " with metrics: block_device_errors_total, block_kmsg_last_seq");

  std::signal(SIGINT, sig_handler);
  std::signal(SIGTERM, sig_handler);
  //

  while (!g_stop.load()) {
    int pr = ::poll(&pfd, 1, 1000);
    if (pr < 0) {
      if (errno == EINTR) {
          continue;
      }
      log_error(std::string("poll(/dev/kmsg) failed: ") + last_errno_string());
      break;
    }
    if (pr == 0) {
      continue;
    }

    if (pfd.revents & POLLIN) {
      Record r;
      if (!read_kmsg_record(kfd, r)) continue;

      if (r.seq > st.last_seq) {
        st.last_seq = r.seq;
        if (!atomic_write_state(state_path, st)) {
            log_error("failed to update state file: " + state_path +
                      ", last_seq=" + std::to_string(st.last_seq));
        }
        if (g_last_seq_gauge) {
          g_last_seq_gauge->Set(static_cast<double>(r.seq));
        }
      } else {
        continue;
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

      pm::Counter* c = get_error_counter(host, subsystem, device);
      c->Increment();
    }
  }

  ::close(kfd);
  std::cerr << "[blockmon-exporter] exiting\n";
  return 0;
}

static std::string getenv_or(const char* name, const char* def) {
  const char* v = std::getenv(name);
  if (v && *v) return std::string(v);
  return std::string(def);
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
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return false;
        }
        log_warn(std::string("read(/dev/kmsg) failed: ") + last_errno_string());
        return false;
    }
    if (n == 0) {
        log_warn("read(/dev/kmsg) returned 0 bytes (EOF?)");
        return false;
    }

    buf[n] = 0;
    std::string line(buf);
    auto semi = line.find(';');
    if (semi == std::string::npos) {
        log_debug("kmsg line without ';', skipping: " + line);
        return false;
    }
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

// Prometheus funcs

static pm::Counter* get_error_counter(const std::string& host,
                                      const std::string& subsystem,
                                      const std::string& device) {
  std::lock_guard<std::mutex> lk(g_metrics_mu);
  MetricKey key{subsystem, device};
  auto it = g_errors_by_dev.find(key);
  if (it != g_errors_by_dev.end()) {
    return it->second;
  }
  auto& ctr = g_errors_family->Add({
      {"host", host},
      {"device", device},
      {"subsystem", subsystem},
      {"source", "kmsg"},
  });
  g_errors_by_dev[key] = &ctr;
  return &ctr;
}

static void sig_handler(int) {
  g_stop.store(true);
}
//
