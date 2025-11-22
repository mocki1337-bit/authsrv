// main.cpp
// Minimal self-contained server implementation without nlohmann::json
// Uses cpp-httplib (single-header), sqlite3, libcurl (for SendGrid), OpenSSL for SHA256
// Compile with: g++ -std=c++17 main.cpp -o authsrv -lsqlite3 -lcurl -lssl -lcrypto -pthread

#include <httplib.h>
#include <sqlite3.h>
#include <curl/curl.h>
#include <openssl/sha.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <optional>
#include <random>
#include <ctime>
#include <map>
#include <algorithm>
#include <cstring>

// ---------- Helper: naive JSON field extractor (for simple JSON objects) ----------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) ++a;
    while (b > a && isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

// Extracts a string field value from a JSON-like body for key.
// Works for simple cases: {"key":"value", ...} and with or without spaces.
// Returns empty optional if not found.
std::optional<std::string> extract_json_string(const std::string& body, const std::string& key) {
    // search for "key"
    std::string pattern = "\"" + key + "\"";
    size_t pos = body.find(pattern);
    if (pos == std::string::npos) return std::nullopt;
    pos = body.find(':', pos + pattern.size());
    if (pos == std::string::npos) return std::nullopt;
    // skip whitespace
    ++pos;
    while (pos < body.size() && isspace((unsigned char)body[pos])) ++pos;
    if (pos >= body.size()) return std::nullopt;
    if (body[pos] != '\"') {
        // not a quoted string; try to parse simple token (number, boolean, null)
        size_t start = pos;
        while (pos < body.size() && body[pos] != ',' && body[pos] != '}' && !isspace((unsigned char)body[pos])) ++pos;
        return trim(body.substr(start, pos - start));
    }
    // parse quoted string
    ++pos;
    std::ostringstream out;
    while (pos < body.size()) {
        char c = body[pos++];
        if (c == '\\' && pos < body.size()) {
            // handle simple escapes \" \\ \/ \b \f \n \r \t and unicode skipped
            char esc = body[pos++];
            switch (esc) {
            case '\"': out << '\"'; break;
            case '\\': out << '\\'; break;
            case '/': out << '/'; break;
            case 'b': out << '\b'; break;
            case 'f': out << '\f'; break;
            case 'n': out << '\n'; break;
            case 'r': out << '\r'; break;
            case 't': out << '\t'; break;
            default:
                // unknown escape: include literally
                out << esc;
            }
        }
        else if (c == '\"') {
            break;
        }
        else {
            out << c;
        }
    }
    return out.str();
}

// set of helper functions to build JSON strings manually
std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
        case '\"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                // control characters -> unicode escape
                char buf[8];
                sprintf(buf, "\\u%04x", (unsigned char)c);
                o << buf;
            }
            else {
                o << c;
            }
        }
    }
    return o.str();
}

std::string make_json_profile(const std::string& email, const std::string& avatar) {
    std::ostringstream out;
    out << "{";
    out << "\"ok\":true,";
    out << "\"profile\":{";
    out << "\"email\":\"" << json_escape(email) << "\",";
    out << "\"avatar\":\"" << json_escape(avatar) << "\"";
    out << "}}";
    return out.str();
}

std::string make_json_token(const std::string& token, const std::string& email, const std::string& avatar) {
    std::ostringstream out;
    out << "{";
    out << "\"ok\":true,";
    out << "\"token\":\"" << json_escape(token) << "\",";
    out << "\"profile\":{";
    out << "\"email\":\"" << json_escape(email) << "\",";
    out << "\"avatar\":\"" << json_escape(avatar) << "\"";
    out << "}}";
    return out.str();
}

std::string make_json_ok() {
    return "{\"ok\":true}";
}

std::string make_json_error(const std::string& msg) {
    std::ostringstream out;
    out << "{\"ok\":false,\"error\":\"" << json_escape(msg) << "\"}";
    return out.str();
}

// ---------- Password hashing (SHA-256 hex) ----------
std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

// ---------- Token generation ----------
std::string gen_token(size_t len = 32) {
    static std::mt19937_64 rng((unsigned)time(nullptr) ^ std::random_device{}());
    static const char* chars = "0123456789abcdef";
    std::string t;
    t.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        t.push_back(chars[rng() % 16]);
    }
    return t;
}

// ---------- SQLite wrapper ----------
struct DB {
    sqlite3* db = nullptr;
    bool open(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            std::cerr << "Can't open DB: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        // enable foreign keys maybe
        sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
        return true;
    }
    void close() {
        if (db) sqlite3_close(db);
        db = nullptr;
    }
    bool exec(const std::string& sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error: " << (err ? err : "(null)") << std::endl;
            sqlite3_free(err);
            return false;
        }
        return true;
    }
    ~DB() { close(); }
};

bool ensure_tables(DB& db) {
    const char* sql_users =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "email TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL, "
        "avatar TEXT DEFAULT ''"
        ");";
    return db.exec(sql_users);
}

struct User {
    int id = 0;
    std::string email;
    std::string password_hash;
    std::string avatar;
};

std::optional<User> find_user_by_email(DB& db, const std::string& email) {
    const char* sql = "SELECT id, email, password, avatar FROM users WHERE email = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<User> result = std::nullopt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        User u;
        u.id = sqlite3_column_int(stmt, 0);
        const unsigned char* e = sqlite3_column_text(stmt, 1);
        const unsigned char* p = sqlite3_column_text(stmt, 2);
        const unsigned char* a = sqlite3_column_text(stmt, 3);
        u.email = e ? reinterpret_cast<const char*>(e) : "";
        u.password_hash = p ? reinterpret_cast<const char*>(p) : "";
        u.avatar = a ? reinterpret_cast<const char*>(a) : "";
        result = u;
    }
    sqlite3_finalize(stmt);
    return result;
}

bool create_user(DB& db, const std::string& email, const std::string& password_hash, const std::string& avatar = "") {
    const char* sql = "INSERT INTO users (email, password, avatar) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, avatar.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

// ---------- SendGrid email via libcurl (optional) ----------
bool send_email_sendgrid(const std::string& to_email, const std::string& subject, const std::string& html_body) {
    const char* api_key = getenv("SENDGRID_API_KEY");
    const char* from_email = getenv("SENDGRID_FROM"); // optional, set env
    if (!api_key || !from_email) {
        // no API key configured
        std::cerr << "SendGrid API key or FROM not set\n";
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    struct curl_slist* headers = nullptr;
    std::string auth = std::string("Authorization: Bearer ") + api_key;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth.c_str());

    // Build SendGrid JSON payload manually (simple)
    std::ostringstream payload;
    payload << "{";
    payload << "\"personalizations\":[{\"to\":[{\"email\":\"" << json_escape(to_email) << "\"}]}],";
    payload << "\"from\":{\"email\":\"" << json_escape(from_email) << "\"},";
    payload << "\"subject\":\"" << json_escape(subject) << "\",";
    payload << "\"content\":[{\"type\":\"text/html\",\"value\":\"" << json_escape(html_body) << "\"}]";
    payload << "}";

    std::string data = payload.str();

    curl_easy_setopt(curl, CURLOPT_URL, "https://api.sendgrid.com/v3/mail/send");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "curl error: " << curl_easy_strerror(res) << std::endl;
        return false;
    }
    if (http_code >= 200 && http_code < 300) return true;
    std::cerr << "SendGrid returned HTTP " << http_code << std::endl;
    return false;
}

// ---------- Application state ----------
struct App {
    DB db;
    std::map<std::string, std::string> tokens; // token -> email
};

int main(int argc, char** argv) {
    // Initialize curl globally (for SendGrid)
    curl_global_init(CURL_GLOBAL_ALL);

    App app;
    // open /data/auth.db or ./auth.db
    std::string dbpath = "./auth.db";
    if (!app.db.open(dbpath)) {
        std::cerr << "Failed to open database at " << dbpath << std::endl;
        return 1;
    }
    if (!ensure_tables(app.db)) {
        std::cerr << "Failed to ensure DB tables\n";
        return 1;
    }

    httplib::Server svr;

    // REGISTER endpoint: expects JSON with "email" and "password"
    svr.Post("/register", [&](const httplib::Request& req, httplib::Response& res) {
        auto email_opt = extract_json_string(req.body, "email");
        auto password_opt = extract_json_string(req.body, "password");
        if (!email_opt || !password_opt) {
            res.set_content(make_json_error("Missing email or password"), "application/json");
            return;
        }
        std::string email = *email_opt;
        std::string password = *password_opt;
        if (email.empty() || password.empty()) {
            res.set_content(make_json_error("Empty email or password"), "application/json");
            return;
        }
        // check existing
        if (find_user_by_email(app.db, email)) {
            res.set_content(make_json_error("User already exists"), "application/json");
            return;
        }
        std::string pass_hash = sha256_hex(password);
        if (!create_user(app.db, email, pass_hash, "")) {
            res.set_content(make_json_error("Failed to create user"), "application/json");
            return;
        }
        res.set_content(make_json_ok(), "application/json");
        });

    // LOGIN endpoint: expects JSON with "email" and "password"
    svr.Post("/login", [&](const httplib::Request& req, httplib::Response& res) {
        auto email_opt = extract_json_string(req.body, "email");
        auto password_opt = extract_json_string(req.body, "password");
        if (!email_opt || !password_opt) {
            res.set_content(make_json_error("Missing email or password"), "application/json");
            return;
        }
        std::string email = *email_opt;
        std::string password = *password_opt;
        auto uopt = find_user_by_email(app.db, email);
        if (!uopt) {
            res.set_content(make_json_error("Invalid credentials"), "application/json");
            return;
        }
        User u = *uopt;
        std::string hash = sha256_hex(password);
        if (hash != u.password_hash) {
            res.set_content(make_json_error("Invalid credentials"), "application/json");
            return;
        }
        std::string token = gen_token(40);
        app.tokens[token] = u.email;

        res.set_content(make_json_token(token, u.email, u.avatar), "application/json");
        });

    // PROFILE endpoint: GET with header Authorization: Bearer <token>
    svr.Get("/profile", [&](const httplib::Request& req, httplib::Response& res) {
        auto auth_it = req.headers.find("Authorization");
        if (auth_it == req.headers.end()) {
            res.set_content(make_json_error("Missing Authorization header"), "application/json");
            return;
        }
        std::string auth = auth_it->second;
        const std::string prefix = "Bearer ";
        if (auth.rfind(prefix, 0) != 0) {
            res.set_content(make_json_error("Invalid Authorization header"), "application/json");
            return;
        }
        std::string token = auth.substr(prefix.size());
        auto it = app.tokens.find(token);
        if (it == app.tokens.end()) {
            res.set_content(make_json_error("Invalid token"), "application/json");
            return;
        }
        std::string email = it->second;
        auto uopt = find_user_by_email(app.db, email);
        if (!uopt) {
            res.set_content(make_json_error("User not found"), "application/json");
            return;
        }
        User u = *uopt;
        res.set_content(make_json_profile(u.email, u.avatar), "application/json");
        });

    // Update profile (example): POST /profile/update with token header and optional avatar
    svr.Post("/profile/update", [&](const httplib::Request& req, httplib::Response& res) {
        auto auth_it = req.headers.find("Authorization");
        if (auth_it == req.headers.end()) {
            res.set_content(make_json_error("Missing Authorization header"), "application/json");
            return;
        }
        std::string auth = auth_it->second;
        const std::string prefix = "Bearer ";
        if (auth.rfind(prefix, 0) != 0) {
            res.set_content(make_json_error("Invalid Authorization header"), "application/json");
            return;
        }
        std::string token = auth.substr(prefix.size());
        auto it = app.tokens.find(token);
        if (it == app.tokens.end()) {
            res.set_content(make_json_error("Invalid token"), "application/json");
            return;
        }
        std::string email = it->second;
        auto uopt = find_user_by_email(app.db, email);
        if (!uopt) {
            res.set_content(make_json_error("User not found"), "application/json");
            return;
        }
        User u = *uopt;
        auto avatar_opt = extract_json_string(req.body, "avatar");
        std::string avatar = avatar_opt ? *avatar_opt : u.avatar;

        const char* sql = "UPDATE users SET avatar = ? WHERE email = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(app.db.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            res.set_content(make_json_error("DB error"), "application/json");
            return;
        }
        sqlite3_bind_text(stmt, 1, avatar.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        if (!ok) {
            res.set_content(make_json_error("Failed to update"), "application/json");
            return;
        }
        res.set_content(make_json_profile(email, avatar), "application/json");
        });

    // Forgot password (example) - sends email if configured
    svr.Post("/forgot", [&](const httplib::Request& req, httplib::Response& res) {
        auto email_opt = extract_json_string(req.body, "email");
        if (!email_opt) {
            res.set_content(make_json_error("Missing email"), "application/json");
            return;
        }
        std::string email = *email_opt;
        auto uopt = find_user_by_email(app.db, email);
        if (!uopt) {
            // do not reveal information
            res.set_content(make_json_ok(), "application/json");
            return;
        }
        std::string code = gen_token(8);
        // In a real app, store reset tokens with expiration. Here we send in email body.
        std::ostringstream html;
        html << "<p>Your password reset code: <b>" << json_escape(code) << "</b></p>";
        bool sent = send_email_sendgrid(email, "Password reset", html.str());
        if (!sent) {
            // still return ok to not leak existence
            res.set_content(make_json_ok(), "application/json");
            return;
        }
        res.set_content(make_json_ok(), "application/json");
        });

    // Health check
    svr.Get("/health", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"ok\":true}", "application/json");
        });

    // Listen on port from env PORT or default 8080
    int port = 8080;
    const char* port_env = getenv("PORT");
    if (port_env) {
        try {
            port = std::stoi(port_env);
        }
        catch (...) { port = 8080; }
    }

    std::cout << "Server starting on port " << port << std::endl;
    svr.listen("0.0.0.0", port);

    curl_global_cleanup();
    return 0;
}
