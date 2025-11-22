
#include "httplib.h"


#include <sqlite3.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdlib>

using json = nlohmann::json;
using namespace std::chrono;

// ---------- Utilities ----------
static std::string getenv_or(const char* name, const std::string& def = "") {
    const char* v = std::getenv(name);
    return v ? std::string(v) : def;
}
static long now_ts() {
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// SHA256 hex
std::string sha256_hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        os << std::setw(2) << (int)hash[i];
    }
    return os.str();
}

// Random 6-digit code
std::string gen_code6() {
    unsigned int num = 0;
    if (RAND_bytes((unsigned char*)&num, sizeof(num)) != 1) {
        num = (unsigned int)std::rand();
    }
    num = num % 1000000;
    std::ostringstream os; os << std::setw(6) << std::setfill('0') << num;
    return os.str();
}

// Random hex token (n bytes)
std::string rand_hex(size_t n) {
    std::vector<unsigned char> buf(n);
    if (RAND_bytes(buf.data(), (int)buf.size()) != 1) {
        for (size_t i = 0; i < n; ++i) buf[i] = (unsigned char)(std::rand() & 0xFF);
    }
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (auto c : buf) os << std::setw(2) << (int)c;
    return os.str();
}

// libcurl send via SendGrid
bool send_email_sendgrid(const std::string& to, const std::string& subject, const std::string& body_html) {
    std::string api_key = getenv_or("SENDGRID_API_KEY");
    std::string sender = getenv_or("SENDER_EMAIL");
    if (api_key.empty() || sender.empty()) {
        // In dev environment we don't fail hard; caller may log
        std::cerr << "[WARN] SENDGRID_API_KEY or SENDER_EMAIL not set\n";
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string url = "https://api.sendgrid.com/v3/mail/send";
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    json payload = {
      {"personalizations", json::array({
        { { "to", json::array({ { {"email", to} } }) } }
      })},
      {"from", { {"email", sender} }},
      {"subject", subject},
      {"content", json::array({ { {"type", "text/html"}, {"value", body_html} } }) }
    };

    std::string payload_str = payload.dump();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_str.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)payload_str.size());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "[ERROR] curl error: " << curl_easy_strerror(res) << "\n";
        return false;
    }
    return (http_code >= 200 && http_code < 300);
}

// sqlite exec (no result)
bool exec_sql(sqlite3* db, const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "[SQL ERROR] " << (err ? err : "unknown") << "\n";
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

// ---------- Server ----------
int main() {
    // init OpenSSL PRNG
    RAND_poll();
    std::srand((unsigned int)time(nullptr));

    // DB file in current folder; change path if desired
    std::string db_path = "auth.db";
    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Cannot open SQLite db at " << db_path << "\n";
        return 1;
    }

    // create tables if not present
    exec_sql(db, R"sql(
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      avatar TEXT DEFAULT '',
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  )sql");

    httplib::Server svr;

    // POST /auth/send-code
    svr.Post("/auth/send-code", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            std::string email = j.value("email", std::string());
            if (email.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"email required"})", "application/json");
                return;
            }
            if (email.find('@') == std::string::npos) {
                res.status = 400;
                res.set_content(R"({"error":"invalid email"})", "application/json");
                return;
            }

            // rate limit: codes created in last hour
            sqlite3_stmt* stmt = nullptr;
            std::string sqlCount = "SELECT COUNT(*) FROM auth_codes WHERE email=? AND created_at>?;";
            if (sqlite3_prepare_v2(db, sqlCount.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 2, now_ts() - 3600);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    int cnt = sqlite3_column_int(stmt, 0);
                    sqlite3_finalize(stmt);
                    if (cnt >= 5) {
                        res.status = 429;
                        res.set_content(R"({"error":"rate limit"})", "application/json");
                        return;
                    }
                }
                else {
                    sqlite3_finalize(stmt);
                }
            }

            std::string code = gen_code6();
            std::string salt = getenv_or("AUTH_SALT", "please_change_this_salt");
            std::string hash = sha256_hex(email + ":" + code + ":" + salt);
            long expires = now_ts() + 600; // 10 minutes

            // insert code
            std::string insertSql = "INSERT INTO auth_codes (email, code_hash, expires_at, created_at) VALUES (?,?,?,?);";
            if (sqlite3_prepare_v2(db, insertSql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 3, expires);
                sqlite3_bind_int64(stmt, 4, now_ts());
                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    sqlite3_finalize(stmt);
                    res.status = 500;
                    res.set_content(R"({"error":"db error"})", "application/json");
                    return;
                }
                sqlite3_finalize(stmt);
            }
            else {
                res.status = 500;
                res.set_content(R"({"error":"db prepare failed"})", "application/json");
                return;
            }

            // send email via SendGrid (best-effort)
            std::ostringstream body;
            body << "<p>Ваш код для входа: <strong>" << code << "</strong></p><p>Действителен 10 минут.</p>";
            bool sent = send_email_sendgrid(email, "Код для входа", body.str());
            if (!sent) {
                // During development it's useful to log the code to console (optional)
                std::cerr << "[INFO] Email send failed or not configured; dev code for " << email << " is: " << code << "\n";
            }

            res.status = 200;
            res.set_content(R"({"ok":true})", "application/json");
        }
        catch (std::exception& ex) {
            res.status = 400;
            res.set_content(R"({"error":"invalid json"})", "application/json");
        }
        });

    // POST /auth/verify
    svr.Post("/auth/verify", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            std::string email = j.value("email", std::string());
            std::string code = j.value("code", std::string());
            if (email.empty() || code.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"email and code required"})", "application/json");
                return;
            }
            std::string salt = getenv_or("AUTH_SALT", "please_change_this_salt");
            std::string hash = sha256_hex(email + ":" + code + ":" + salt);

            sqlite3_stmt* stmt = nullptr;
            std::string sel = "SELECT id, code_hash, expires_at, attempts FROM auth_codes WHERE email=? ORDER BY created_at DESC LIMIT 1;";
            if (sqlite3_prepare_v2(db, sel.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    int id = sqlite3_column_int(stmt, 0);
                    const unsigned char* ch = sqlite3_column_text(stmt, 1);
                    long expires = sqlite3_column_int64(stmt, 2);
                    int attempts = sqlite3_column_int(stmt, 3);
                    std::string stored_hash = ch ? (const char*)ch : "";
                    sqlite3_finalize(stmt);

                    if (now_ts() > expires) {
                        res.status = 400;
                        res.set_content(R"({"error":"code expired"})", "application/json");
                        return;
                    }
                    if (attempts >= 10) {
                        res.status = 400;
                        res.set_content(R"({"error":"code locked"})", "application/json");
                        return;
                    }

                    if (stored_hash == hash) {
                        // find or create user
                        int user_id = -1;
                        std::string selUser = "SELECT id FROM users WHERE email=? LIMIT 1;";
                        if (sqlite3_prepare_v2(db, selUser.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                            if (sqlite3_step(stmt) == SQLITE_ROW) user_id = sqlite3_column_int(stmt, 0);
                            sqlite3_finalize(stmt);
                        }
                        if (user_id == -1) {
                            std::string insU = "INSERT INTO users (email, created_at) VALUES (?,?);";
                            if (sqlite3_prepare_v2(db, insU.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                                sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                                sqlite3_bind_int64(stmt, 2, now_ts());
                                if (sqlite3_step(stmt) == SQLITE_DONE) user_id = (int)sqlite3_last_insert_rowid(db);
                                sqlite3_finalize(stmt);
                            }
                        }

                        // create session
                        std::string token = rand_hex(32);
                        long sess_expires = now_ts() + 60 * 60 * 24 * 30; // 30 days
                        std::string insS = "INSERT INTO sessions (user_id, token, expires_at, created_at) VALUES (?,?,?,?);";
                        if (sqlite3_prepare_v2(db, insS.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_int(stmt, 1, user_id);
                            sqlite3_bind_text(stmt, 2, token.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_int64(stmt, 3, sess_expires);
                            sqlite3_bind_int64(stmt, 4, now_ts());
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }

                        // delete used code
                        std::string del = "DELETE FROM auth_codes WHERE id = ?;";
                        if (sqlite3_prepare_v2(db, del.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_int(stmt, 1, id);
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }

                        // fetch avatar
                        std::string avatar = "";
                        std::string q = "SELECT avatar FROM users WHERE id=? LIMIT 1;";
                        if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_int(stmt, 1, user_id);
                            if (sqlite3_step(stmt) == SQLITE_ROW) {
                                const unsigned char* av = sqlite3_column_text(stmt, 0);
                                avatar = av ? (const char*)av : "";
                            }
                            sqlite3_finalize(stmt);
                        }

                        json out = { {"ok", true}, {"token", token}, {"profile", { {"email", email}, {"avatar", avatar} }} };
                        res.status = 200;
                        res.set_content(out.dump(), "application/json");
                        return;
                    }
                    else {
                        // increment attempts
                        std::string upd = "UPDATE auth_codes SET attempts = attempts + 1 WHERE id = ?;";
                        if (sqlite3_prepare_v2(db, upd.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_int(stmt, 1, id);
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                        res.status = 400;
                        res.set_content(R"({"error":"invalid code"})", "application/json");
                        return;
                    }
                }
                else {
                    sqlite3_finalize(stmt);
                    res.status = 400;
                    res.set_content(R"({"error":"no code found"})", "application/json");
                    return;
                }
            }
            else {
                res.status = 500;
                res.set_content(R"({"error":"db error"})", "application/json");
                return;
            }
        }
        catch (std::exception& ex) {
            res.status = 400;
            res.set_content(R"({"error":"invalid json"})", "application/json");
        }
        });

    // GET /me
    svr.Get("/me", [&](const httplib::Request& req, httplib::Response& res) {
        auto auth_it = req.get_header_value("Authorization");
        if (auth_it.empty()) {
            res.status = 401;
            res.set_content(R"({"error":"unauthorized"})", "application/json");
            return;
        }
        std::string token;
        if (auth_it.rfind("Bearer ", 0) == 0) token = auth_it.substr(7);
        if (token.empty()) {
            res.status = 401;
            res.set_content(R"({"error":"invalid token"})", "application/json");
            return;
        }

        sqlite3_stmt* stmt = nullptr;
        std::string q = "SELECT u.email, u.avatar FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token = ? AND s.expires_at > ? LIMIT 1;";
        if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, now_ts());
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* em = sqlite3_column_text(stmt, 0);
                const unsigned char* av = sqlite3_column_text(stmt, 1);
                json out = { {"ok", true}, {"profile", { {"email", em ? (const char*)em : ""}, {"avatar", av ? (const char*)av : ""} }} };
                sqlite3_finalize(stmt);
                res.status = 200;
                res.set_content(out.dump(), "application/json");
                return;
            }
            sqlite3_finalize(stmt);
        }

        res.status = 401;
        res.set_content(R"({"error":"invalid token"})", "application/json");
        });

    std::cout << "Auth server listening on http://0.0.0.0:8080\n";
    // --- CORS support (simple)
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        if (req.method == "OPTIONS") {
            res.status = 200;
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
        });

    // ensure uploads directory exists
    {
        const char* uploads_dir = "uploads";
#ifdef _WIN32
        std::string cmd = std::string("if not exist ") + uploads_dir + " mkdir " + uploads_dir;
        system(cmd.c_str());
#else
        struct stat st = { 0 };
        if (stat(uploads_dir, &st) == -1) mkdir(uploads_dir, 0755);
#endif
    }

    // Serve uploaded files under /uploads
    svr.set_mount_point("/uploads", "./uploads");

    // POST /user/avatar
    // Expects multipart/form-data with fields: token (text), avatar (file)
    
    svr.listen("0.0.0.0", 8080);

    sqlite3_close(db);
    return 0;
}
