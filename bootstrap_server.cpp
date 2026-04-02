#include "bootstrap_server.h"


Bootstrap_Server::Bootstrap_Server(quint16 port, QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_ws_server(new QWebSocketServer("Hogrin WS", QWebSocketServer::NonSecureMode, this))
    , m_port(port)
    , m_cleanup_timer(new QTimer(this))
    , m_ip_reset_timer(new QTimer(this))
{
    if (sodium_init() < 0) qWarning() << "libsodium init failed!";
    if (!init_database())  qWarning() << "SQLite init failed!";
    if (!init_postgres())  qWarning() << "PostgreSQL init failed!";

    connect(m_cleanup_timer, &QTimer::timeout, this, &Bootstrap_Server::cleanup_old_messages);
    connect(m_ip_reset_timer, &QTimer::timeout, this, &Bootstrap_Server::reset_ip_counters);

    m_cleanup_timer->start(60 * 60 * 1000);
    m_ip_reset_timer->start(60 * 60 * 1000);
}

bool Bootstrap_Server::start()
{
    // TCP (IPv6)
    if (!m_server->listen(QHostAddress::Any, m_port)) {
        qDebug() << "Failed to start TCP:" << m_server->errorString();
        return false;
    }
    connect(m_server, &QTcpServer::newConnection, this, &Bootstrap_Server::handle_new_connection);

    // WS (IPv4 Fallback - Cloudflare)
    quint16 ws_port = m_port + 1;
    if (!m_ws_server->listen(QHostAddress::Any, ws_port)) {
        qDebug() << "Failed to start WS:" << m_ws_server->errorString();
        return false;
    }
    connect(m_ws_server, &QWebSocketServer::newConnection, this, &Bootstrap_Server::handle_new_ws_connection);

    qDebug() << "Bootstrap TCP started on" << m_port << "| WS on" << ws_port;
    return true;
}

// ── connection handling ───────────────────────────────────────────────────────

void Bootstrap_Server::handle_new_connection()
{
    while (m_server->hasPendingConnections()) {
        QTcpSocket *socket = m_server->nextPendingConnection();
        qDebug() << "New TCP connection from:" << socket->peerAddress().toString();

        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
            handle_incoming_data(socket);
        });

        connect(socket, &QTcpSocket::disconnected, this, [this, socket]() {
            qDebug() << "TCP Client disconnected:" << socket->peerAddress().toString();
            m_buffers.remove(socket);
            socket->deleteLater();
        });
    }
}

void Bootstrap_Server::handle_new_ws_connection()
{
    while (m_ws_server->hasPendingConnections()) {
        QWebSocket *socket = m_ws_server->nextPendingConnection();
        QNetworkRequest req = socket->request();
        QString ip;

        if (req.hasRawHeader("CF-Connecting-IP")) {
            ip = QString::fromUtf8(req.rawHeader("CF-Connecting-IP")).trimmed();
        } else if (req.hasRawHeader("X-Forwarded-For")) {
            ip = QString::fromUtf8(req.rawHeader("X-Forwarded-For")).split(',').first().trimmed();
        } else {
            ip = normalize_address(socket->peerAddress().toString());
        }

        qDebug() << "New WS connection from:" << ip;

        connect(socket, &QWebSocket::textMessageReceived, this, [this, socket, ip](const QString &msg) {
            handle_ws_data(socket, ip, msg);
        });

        connect(socket, &QWebSocket::disconnected, this, [this, socket, ip]() {
            qDebug() << "WS Client disconnected:" << ip;
            socket->deleteLater();
        });
    }
}

void Bootstrap_Server::handle_incoming_data(QTcpSocket *socket)
{
    m_buffers[socket] += socket->readAll();

    while (true) {
        int newline = m_buffers[socket].indexOf('\n');
        if (newline == -1) break;

        QByteArray line_bytes = m_buffers[socket].left(newline);
        m_buffers[socket]     = m_buffers[socket].mid(newline + 1);

        QString line = QString::fromUtf8(line_bytes).trimmed();
        if (!line.isEmpty())
            handle_data(socket, line);
    }
}

// ── TRANSPORT WRAPPERS ────────────────────────────────────────────────────────

void Bootstrap_Server::handle_data(QTcpSocket *socket, const QString &msg)
{
    QString ip = normalize_address(socket->peerAddress().toString());
    core_process_message(ip, msg, [this, socket](const QString &response) {
        send_response(socket, response);
    });
}

void Bootstrap_Server::handle_ws_data(QWebSocket *socket, const QString &ip, const QString &msg)
{
    core_process_message(ip, msg, [socket](const QString &response) {
        socket->sendTextMessage(response);
    });
}

void Bootstrap_Server::send_response(QTcpSocket *socket, const QString &response)
{
    socket->write((response + "\n").toUtf8());
}

// ── CORE LOGIC ────────────────────────────────────────────────────────────────

void Bootstrap_Server::core_process_message(const QString &ip, const QString &msg, std::function<void(const QString&)> reply)
{
    qDebug() << "Received:" << msg.left(120);

    if (msg.startsWith("AUTH_REGISTER:")) {
        QString rest = msg.mid(14);
        int sep = rest.indexOf(':');
        if (sep == -1) { reply("AUTH_REG_ERR:bad_format"); return; }
        handle_auth_register(rest.left(sep), rest.mid(sep + 1), reply);
    }
    else if (msg.startsWith("AUTH_LOGIN:")) {
        QString rest = msg.mid(11);
        int sep = rest.indexOf(':');
        if (sep == -1) { reply("AUTH_LOGIN_ERR:bad_format"); return; }
        handle_auth_login(rest.left(sep), rest.mid(sep + 1), reply);
    }
    else if (msg.startsWith("AUTH_VERIFY:")) {
        handle_auth_verify(msg.mid(12), reply);
    }
    else if (msg.startsWith("AUTH_LOGOUT:")) {
        handle_auth_logout(msg.mid(12), reply);
    }
    else if (msg.startsWith("REGISTER:")) {
        QStringList parts = msg.split(":");
        if (parts.size() == 4) {
            QString nickname = parts[1];
            QString port     = parts[2];
            QString pubkey   = parts[3];
            QString address  = ip + "|" + port;

            QSqlQuery q(m_db);
            q.prepare("INSERT INTO peers (nickname, address, pubkey, last_seen) "
                      "VALUES (:nick, :addr, :pubkey, :ts) "
                      "ON CONFLICT(nickname) DO UPDATE SET "
                      "address = excluded.address, pubkey = excluded.pubkey, last_seen = excluded.last_seen");
            q.bindValue(":nick",   nickname);
            q.bindValue(":addr",   address);
            q.bindValue(":pubkey", pubkey);
            q.bindValue(":ts",     QDateTime::currentSecsSinceEpoch());

            if (!q.exec()) qWarning() << "REGISTER failed:" << q.lastError().text();
            else qDebug() << "Registered:" << nickname << "->" << address;

            reply("REGISTER_OK:" + ip);
        }
    }
    else if (msg.startsWith("FIND:")) {
        QString nickname = msg.mid(5);

        QSqlQuery q(m_db);
        q.prepare("SELECT address, pubkey, last_seen FROM peers WHERE nickname = :nick");
        q.bindValue(":nick", nickname);
        q.exec();

        if (q.next()) {
            qint64 last_seen = q.value(2).toLongLong();
            qint64 now = QDateTime::currentSecsSinceEpoch();

            if (now - last_seen <= 15) {
                reply("FOUND:" + q.value(0).toString() + "|" + q.value(1).toString());
            } else {
                reply("NOT_FOUND");
            }
        } else {
            reply("NOT_FOUND");
        }
    }
    else if (msg.startsWith("STORE:")) {
        if (m_ip_store_count[ip] >= Config::RELAY_MAX_STORE_PER_IP) {
            reply("ERROR:RATE_LIMITED");
            return;
        }

        int first_colon = msg.indexOf(':', 6);
        if (first_colon == -1) return;

        QString    nickname = msg.mid(6, first_colon - 6);
        QByteArray blob     = QByteArray::fromHex(msg.mid(first_colon + 1).toUtf8());

        if (blob.isEmpty())                             { reply("ERROR:EMPTY_BLOB"); return; }
        if (blob.size() > Config::RELAY_MAX_BLOB_SIZE)  { reply("ERROR:TOO_LARGE");  return; }

        QSqlQuery count_q(m_db);
        count_q.prepare("SELECT COUNT(*) FROM messages WHERE nickname = :nick");
        count_q.bindValue(":nick", nickname);
        count_q.exec(); count_q.next();
        if (count_q.value(0).toInt() >= Config::RELAY_MAX_QUEUE) {
            reply("ERROR:QUEUE_FULL");
            return;
        }

        QSqlQuery q(m_db);
        q.prepare("INSERT INTO messages (nickname, blob, stored_at) VALUES (:nick, :blob, :ts)");
        q.bindValue(":nick", nickname);
        q.bindValue(":blob", blob);
        q.bindValue(":ts",   QDateTime::currentSecsSinceEpoch());
        q.exec();

        m_ip_store_count[ip]++;
        reply("OK");
    }
    else if (msg.startsWith("FETCH:")) {
        QString nickname = msg.mid(6);

        QSqlQuery upd(m_db);
        upd.prepare("UPDATE peers SET last_seen = :ts WHERE nickname = :nick");
        upd.bindValue(":ts", QDateTime::currentSecsSinceEpoch());
        upd.bindValue(":nick", nickname);
        upd.exec();

        QSqlQuery q(m_db);
        q.prepare("SELECT blob FROM messages WHERE nickname = :nick ORDER BY id ASC");
        q.bindValue(":nick", nickname);
        q.exec();

        QStringList responses;
        while (q.next())
            responses << "MSG:" + QString::fromUtf8(q.value(0).toByteArray().toHex());

        if (responses.isEmpty()) { reply("EMPTY"); return; }

        QSqlQuery del(m_db);
        del.prepare("DELETE FROM messages WHERE nickname = :nick");
        del.bindValue(":nick", nickname);
        del.exec();

        for (const QString &r : responses) reply(r);

        qDebug() << "Fetched" << responses.size() << "messages for:" << nickname;
    }
    else if (msg.startsWith("UNREGISTER:")) {
        QString nickname = msg.mid(11);

        QSqlQuery q(m_db);
        q.prepare("DELETE FROM peers WHERE nickname = :nick");
        q.bindValue(":nick", nickname);

        if (q.exec() && q.numRowsAffected() > 0) reply("OK");
        else reply("NOT_FOUND");

        qDebug() << "Unregistered:" << nickname;
    }
}

// ── AUTH handlers ─────────────────────────────────────────────────────────────

void Bootstrap_Server::handle_auth_register(const QString &nickname, const QString &password, std::function<void(const QString&)> reply)
{
    if (nickname.isEmpty() || password.isEmpty()) {
        reply("AUTH_REG_ERR:empty_fields");
        return;
    }

    QSqlQuery check(m_pg);
    check.prepare("SELECT 1 FROM users WHERE nickname = :nick LIMIT 1");
    check.bindValue(":nick", nickname);
    check.exec();
    if (check.next()) {
        reply("AUTH_REG_ERR:already_exists");
        return;
    }

    char hash[crypto_pwhash_STRBYTES];
    QByteArray pw = password.toUtf8();
    if (crypto_pwhash_str(hash, pw.constData(), pw.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        reply("AUTH_REG_ERR:server_error");
        return;
    }

    QSqlQuery q(m_pg);
    q.prepare("INSERT INTO users (nickname, password_hash) VALUES (:nick, :hash)");
    q.bindValue(":nick", nickname);
    q.bindValue(":hash", QString::fromUtf8(hash));

    if (!q.exec()) {
        reply("AUTH_REG_ERR:server_error");
        return;
    }

    qDebug() << "AUTH_REGISTER OK:" << nickname;
    reply("AUTH_REG_OK");
}

void Bootstrap_Server::handle_auth_login(const QString &nickname, const QString &password, std::function<void(const QString&)> reply)
{
    QSqlQuery q(m_pg);
    q.prepare("SELECT password_hash FROM users WHERE nickname = :nick AND is_banned = FALSE LIMIT 1");
    q.bindValue(":nick", nickname);
    q.exec();

    if (!q.next()) {
        reply("AUTH_LOGIN_ERR:invalid");
        return;
    }

    QString stored_hash = q.value(0).toString();
    QByteArray pw = password.toUtf8();

    if (crypto_pwhash_str_verify(stored_hash.toUtf8().constData(), pw.constData(), pw.size()) != 0) {
        reply("AUTH_LOGIN_ERR:invalid");
        return;
    }

    QSqlQuery upd(m_pg);
    upd.prepare("UPDATE users SET last_seen = NOW() WHERE nickname = :nick");
    upd.bindValue(":nick", nickname);
    upd.exec();

    QString token = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QSqlQuery s(m_db);
    s.prepare("INSERT INTO sessions (token, nickname, created_at) VALUES (:token, :nick, :ts)");
    s.bindValue(":token", token);
    s.bindValue(":nick",  nickname);
    s.bindValue(":ts",    QDateTime::currentSecsSinceEpoch());
    s.exec();

    qDebug() << "AUTH_LOGIN OK:" << nickname;
    reply("AUTH_LOGIN_OK:" + token);
}

void Bootstrap_Server::handle_auth_verify(const QString &token, std::function<void(const QString&)> reply)
{
    QSqlQuery q(m_db);
    q.prepare("SELECT nickname, created_at FROM sessions WHERE token = :token LIMIT 1");
    q.bindValue(":token", token);
    q.exec();

    if (!q.next()) {
        reply("AUTH_VERIFY_ERR:invalid");
        return;
    }

    QString nickname   = q.value(0).toString();
    qint64  created_at = q.value(1).toLongLong();

    qint64 age = QDateTime::currentSecsSinceEpoch() - created_at;
    if (age > 30LL * 24 * 3600) {
        QSqlQuery del(m_db);
        del.prepare("DELETE FROM sessions WHERE token = :token");
        del.bindValue(":token", token);
        del.exec();
        reply("AUTH_VERIFY_ERR:expired");
        return;
    }

    reply("AUTH_VERIFY_OK:" + nickname);
}

void Bootstrap_Server::handle_auth_logout(const QString &token, std::function<void(const QString&)> reply)
{
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM sessions WHERE token = :token");
    q.bindValue(":token", token);
    q.exec();
    reply("AUTH_LOGOUT_OK");
}

// ── helpers ───────────────────────────────────────────────────────────────────

QString Bootstrap_Server::normalize_address(const QString &address)
{
    if (address.startsWith("::ffff:")) return address.mid(7);
    return address;
}

void Bootstrap_Server::cleanup_old_messages()
{
    qint64 threshold = QDateTime::currentSecsSinceEpoch() - (Config::RELAY_MESSAGE_TTL_DAYS * 86400LL);
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM messages WHERE stored_at < :threshold");
    q.bindValue(":threshold", threshold);
    q.exec();

    qint64 session_threshold = QDateTime::currentSecsSinceEpoch() - 30LL * 24 * 3600;
    QSqlQuery sq(m_db);
    sq.prepare("DELETE FROM sessions WHERE created_at < :threshold");
    sq.bindValue(":threshold", session_threshold);
    sq.exec();
}

void Bootstrap_Server::reset_ip_counters()
{
    m_ip_store_count.clear();
}

bool Bootstrap_Server::init_database()
{
    m_db = QSqlDatabase::addDatabase("QSQLITE", "bootstrap");
    m_db.setDatabaseName("bootstrap.db");

    if (!m_db.open()) return false;

    QSqlQuery q(m_db);
    q.exec("CREATE TABLE IF NOT EXISTS peers (nickname TEXT PRIMARY KEY, address TEXT NOT NULL, pubkey TEXT NOT NULL, last_seen INTEGER NOT NULL)");
    q.exec("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, nickname TEXT NOT NULL, blob BLOB NOT NULL, stored_at INTEGER NOT NULL)");
    q.exec("CREATE INDEX IF NOT EXISTS idx_messages_nickname ON messages(nickname)");
    q.exec("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, nickname TEXT NOT NULL, created_at INTEGER NOT NULL)");
    q.exec("CREATE INDEX IF NOT EXISTS idx_sessions_nickname ON sessions(nickname)");
    return true;
}

bool Bootstrap_Server::init_postgres()
{
    m_pg = QSqlDatabase::addDatabase("QPSQL", "hogrin_pg");
    m_pg.setHostName(Config::db_host());
    m_pg.setPort(Config::db_port());
    m_pg.setDatabaseName(Config::db_name());
    m_pg.setUserName(Config::db_user());
    m_pg.setPassword(Config::db_password());

    return m_pg.open();
}