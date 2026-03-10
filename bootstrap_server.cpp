#include "bootstrap_server.h"
#include <QDebug>
#include <QUuid>
#include <sodium.h>

Bootstrap_Server::Bootstrap_Server(quint16 port, QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_port(port)
    , m_cleanup_timer(new QTimer(this))
    , m_ip_reset_timer(new QTimer(this))
{
    if (sodium_init() < 0)
        qWarning() << "libsodium init failed!";

    if (!init_database())
        qWarning() << "SQLite init failed!";

    if (!init_postgres())
        qWarning() << "PostgreSQL init failed!";

    connect(m_cleanup_timer, &QTimer::timeout,
            this, &Bootstrap_Server::cleanup_old_messages);
    connect(m_ip_reset_timer, &QTimer::timeout,
            this, &Bootstrap_Server::reset_ip_counters);

    m_cleanup_timer->start(60 * 60 * 1000);
    m_ip_reset_timer->start(60 * 60 * 1000);
}

bool Bootstrap_Server::start()
{
    if (!m_server->listen(QHostAddress::Any, m_port)) {
        qDebug() << "Failed to start:" << m_server->errorString();
        return false;
    }
    connect(m_server, &QTcpServer::newConnection,
            this, &Bootstrap_Server::handle_new_connection);
    qDebug() << "Bootstrap server started on port" << m_port;
    return true;
}

// ── connection handling ───────────────────────────────────────────────────────

void Bootstrap_Server::handle_new_connection()
{
    while (m_server->hasPendingConnections()) {
        QTcpSocket *socket = m_server->nextPendingConnection();
        qDebug() << "New connection from:" << socket->peerAddress().toString();

        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
            handle_incoming_data(socket);
        });

        connect(socket, &QTcpSocket::disconnected, this, [this, socket]() {
            qDebug() << "Client disconnected:" << socket->peerAddress().toString();
            m_buffers.remove(socket);
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

// ── protocol dispatch ─────────────────────────────────────────────────────────

void Bootstrap_Server::handle_data(QTcpSocket *socket, const QString &msg)
{
    qDebug() << "Received:" << msg.left(120);

    // ── AUTH ─────────────────────────────────────────────────────────────────
    if (msg.startsWith("AUTH_REGISTER:")) {
        QString rest = msg.mid(14);
        int sep = rest.indexOf(':');
        if (sep == -1) { send_response(socket, "AUTH_REG_ERR:bad_format"); return; }
        handle_auth_register(socket, rest.left(sep), rest.mid(sep + 1));
    }
    else if (msg.startsWith("AUTH_LOGIN:")) {
        QString rest = msg.mid(11);
        int sep = rest.indexOf(':');
        if (sep == -1) { send_response(socket, "AUTH_LOGIN_ERR:bad_format"); return; }
        handle_auth_login(socket, rest.left(sep), rest.mid(sep + 1));
    }
    else if (msg.startsWith("AUTH_VERIFY:")) {
        handle_auth_verify(socket, msg.mid(12));
    }
    else if (msg.startsWith("AUTH_LOGOUT:")) {
        handle_auth_logout(socket, msg.mid(12));
    }

    // ── P2P REGISTER ─────────────────────────────────────────────────────────
    else if (msg.startsWith("REGISTER:")) {
        QStringList parts = msg.split(":");
        if (parts.size() == 4) {
            QString nickname = parts[1];
            QString port     = parts[2];
            QString pubkey   = parts[3];
            QString ip       = normalize_address(socket->peerAddress().toString());
            QString address  = ip + "|" + port;

            QSqlQuery q(m_db);
            q.prepare("INSERT INTO peers (nickname, address, pubkey) "
                      "VALUES (:nick, :addr, :pubkey) "
                      "ON CONFLICT(nickname) DO UPDATE SET "
                      "address = excluded.address, pubkey = excluded.pubkey");
            q.bindValue(":nick",   nickname);
            q.bindValue(":addr",   address);
            q.bindValue(":pubkey", pubkey);

            if (!q.exec())
                qWarning() << "REGISTER failed:" << q.lastError().text();
            else
                qDebug() << "Registered:" << nickname << "->" << address;

            send_response(socket, "OK");
        }
    }
    else if (msg.startsWith("FIND:")) {
        QString nickname = msg.mid(5);

        QSqlQuery q(m_db);
        q.prepare("SELECT address, pubkey FROM peers WHERE nickname = :nick");
        q.bindValue(":nick", nickname);
        q.exec();

        if (q.next()) {
            send_response(socket, "FOUND:" + q.value(0).toString()
                          + "|" + q.value(1).toString());
        } else {
            send_response(socket, "NOT_FOUND");
        }
    }

    // ── RELAY ─────────────────────────────────────────────────────────────────
    else if (msg.startsWith("STORE:")) {
        QString ip = normalize_address(socket->peerAddress().toString());

        if (m_ip_store_count[ip] >= Config::RELAY_MAX_STORE_PER_IP) {
            send_response(socket, "ERROR:RATE_LIMITED");
            return;
        }

        int first_colon = msg.indexOf(':', 6);
        if (first_colon == -1) return;

        QString    nickname = msg.mid(6, first_colon - 6);
        QByteArray blob     = QByteArray::fromHex(msg.mid(first_colon + 1).toUtf8());

        if (blob.isEmpty())                             { send_response(socket, "ERROR:EMPTY_BLOB"); return; }
        if (blob.size() > Config::RELAY_MAX_BLOB_SIZE) { send_response(socket, "ERROR:TOO_LARGE");  return; }

        QSqlQuery count_q(m_db);
        count_q.prepare("SELECT COUNT(*) FROM messages WHERE nickname = :nick");
        count_q.bindValue(":nick", nickname);
        count_q.exec(); count_q.next();
        if (count_q.value(0).toInt() >= Config::RELAY_MAX_QUEUE) {
            send_response(socket, "ERROR:QUEUE_FULL");
            return;
        }

        QSqlQuery q(m_db);
        q.prepare("INSERT INTO messages (nickname, blob, stored_at) "
                  "VALUES (:nick, :blob, :ts)");
        q.bindValue(":nick", nickname);
        q.bindValue(":blob", blob);
        q.bindValue(":ts",   QDateTime::currentSecsSinceEpoch());
        q.exec();

        m_ip_store_count[ip]++;
        send_response(socket, "OK");
    }
    else if (msg.startsWith("FETCH:")) {
        QString nickname = msg.mid(6);

        QSqlQuery q(m_db);
        q.prepare("SELECT blob FROM messages WHERE nickname = :nick ORDER BY id ASC");
        q.bindValue(":nick", nickname);
        q.exec();

        QStringList responses;
        while (q.next())
            responses << "MSG:" + QString::fromUtf8(q.value(0).toByteArray().toHex());

        if (responses.isEmpty()) { send_response(socket, "EMPTY"); return; }

        QSqlQuery del(m_db);
        del.prepare("DELETE FROM messages WHERE nickname = :nick");
        del.bindValue(":nick", nickname);
        del.exec();

        for (const QString &r : responses)
            send_response(socket, r);

        qDebug() << "Fetched" << responses.size() << "messages for:" << nickname;
    }
    else if (msg.startsWith("UNREGISTER:")) {
        QString nickname = msg.mid(11);

        QSqlQuery q(m_db);
        q.prepare("DELETE FROM peers WHERE nickname = :nick");
        q.bindValue(":nick", nickname);

        if (q.exec() && q.numRowsAffected() > 0)
            send_response(socket, "OK");
        else
            send_response(socket, "NOT_FOUND");

        qDebug() << "Unregistered:" << nickname;
    }
}

// ── AUTH handlers ─────────────────────────────────────────────────────────────

void Bootstrap_Server::handle_auth_register(QTcpSocket *socket,
                                            const QString &nickname,
                                            const QString &password)
{
    if (nickname.isEmpty() || password.isEmpty()) {
        send_response(socket, "AUTH_REG_ERR:empty_fields");
        return;
    }

    QSqlQuery check(m_pg);
    check.prepare("SELECT 1 FROM users WHERE nickname = :nick LIMIT 1");
    check.bindValue(":nick", nickname);
    check.exec();
    if (check.next()) {
        send_response(socket, "AUTH_REG_ERR:already_exists");
        return;
    }

    char hash[crypto_pwhash_STRBYTES];
    QByteArray pw = password.toUtf8();
    if (crypto_pwhash_str(hash,
                          pw.constData(),
                          pw.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        qWarning() << "AUTH_REGISTER: hashing failed (out of memory?)";
        send_response(socket, "AUTH_REG_ERR:server_error");
        return;
    }

    QSqlQuery q(m_pg);
    q.prepare("INSERT INTO users (nickname, password_hash) VALUES (:nick, :hash)");
    q.bindValue(":nick", nickname);
    q.bindValue(":hash", QString::fromUtf8(hash));

    if (!q.exec()) {
        qWarning() << "AUTH_REGISTER insert failed:" << q.lastError().text();
        send_response(socket, "AUTH_REG_ERR:server_error");
        return;
    }

    qDebug() << "AUTH_REGISTER OK:" << nickname;
    send_response(socket, "AUTH_REG_OK");
}

void Bootstrap_Server::handle_auth_login(QTcpSocket *socket,
                                         const QString &nickname,
                                         const QString &password)
{
    QSqlQuery q(m_pg);
    q.prepare("SELECT password_hash FROM users "
              "WHERE nickname = :nick AND is_banned = FALSE LIMIT 1");
    q.bindValue(":nick", nickname);
    q.exec();

    if (!q.next()) {
        send_response(socket, "AUTH_LOGIN_ERR:invalid");
        return;
    }

    QString stored_hash = q.value(0).toString();
    QByteArray pw = password.toUtf8();

    if (crypto_pwhash_str_verify(stored_hash.toUtf8().constData(),
                                 pw.constData(),
                                 pw.size()) != 0)
    {
        send_response(socket, "AUTH_LOGIN_ERR:invalid");
        return;
    }

    QSqlQuery upd(m_pg);
    upd.prepare("UPDATE users SET last_seen = NOW() WHERE nickname = :nick");
    upd.bindValue(":nick", nickname);
    upd.exec();

    QString token = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QSqlQuery s(m_db);
    s.prepare("INSERT INTO sessions (token, nickname, created_at) "
              "VALUES (:token, :nick, :ts)");
    s.bindValue(":token", token);
    s.bindValue(":nick",  nickname);
    s.bindValue(":ts",    QDateTime::currentSecsSinceEpoch());
    s.exec();

    qDebug() << "AUTH_LOGIN OK:" << nickname;
    send_response(socket, "AUTH_LOGIN_OK:" + token);
}

void Bootstrap_Server::handle_auth_verify(QTcpSocket *socket,
                                          const QString &token)
{
    QSqlQuery q(m_db);
    q.prepare("SELECT nickname, created_at FROM sessions WHERE token = :token LIMIT 1");
    q.bindValue(":token", token);
    q.exec();

    if (!q.next()) {
        send_response(socket, "AUTH_VERIFY_ERR:invalid");
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
        send_response(socket, "AUTH_VERIFY_ERR:expired");
        return;
    }

    qDebug() << "AUTH_VERIFY OK:" << nickname;
    send_response(socket, "AUTH_VERIFY_OK:" + nickname);
}

void Bootstrap_Server::handle_auth_logout(QTcpSocket *socket,
                                          const QString &token)
{
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM sessions WHERE token = :token");
    q.bindValue(":token", token);
    q.exec();

    qDebug() << "AUTH_LOGOUT OK";
    send_response(socket, "AUTH_LOGOUT_OK");
}

// ── helpers ───────────────────────────────────────────────────────────────────

void Bootstrap_Server::send_response(QTcpSocket *socket, const QString &response)
{
    socket->write((response + "\n").toUtf8());
}

QString Bootstrap_Server::normalize_address(const QString &address)
{
    if (address.startsWith("::ffff:"))
        return address.mid(7);
    return address;
}

void Bootstrap_Server::cleanup_old_messages()
{
    qint64 threshold = QDateTime::currentSecsSinceEpoch()
    - (Config::RELAY_MESSAGE_TTL_DAYS * 86400LL);

    QSqlQuery q(m_db);
    q.prepare("DELETE FROM messages WHERE stored_at < :threshold");
    q.bindValue(":threshold", threshold);
    q.exec();

    int removed = q.numRowsAffected();
    if (removed > 0)
        qDebug() << "Cleanup: removed" << removed << "expired messages";

    qint64 session_threshold = QDateTime::currentSecsSinceEpoch() - 30LL * 24 * 3600;
    QSqlQuery sq(m_db);
    sq.prepare("DELETE FROM sessions WHERE created_at < :threshold");
    sq.bindValue(":threshold", session_threshold);
    sq.exec();
}

void Bootstrap_Server::reset_ip_counters()
{
    int count = m_ip_store_count.size();
    m_ip_store_count.clear();
    if (count > 0)
        qDebug() << "IP counters reset for" << count << "addresses";
}

bool Bootstrap_Server::init_database()
{
    m_db = QSqlDatabase::addDatabase("QSQLITE", "bootstrap");
    m_db.setDatabaseName("bootstrap.db");

    if (!m_db.open()) {
        qWarning() << "Failed to open SQLite:" << m_db.lastError().text();
        return false;
    }

    QSqlQuery q(m_db);

    q.exec("CREATE TABLE IF NOT EXISTS peers ("
           "nickname TEXT PRIMARY KEY,"
           "address  TEXT NOT NULL,"
           "pubkey   TEXT NOT NULL"
           ")");

    q.exec("CREATE TABLE IF NOT EXISTS messages ("
           "id        INTEGER PRIMARY KEY AUTOINCREMENT,"
           "nickname  TEXT    NOT NULL,"
           "blob      BLOB    NOT NULL,"
           "stored_at INTEGER NOT NULL"
           ")");

    q.exec("CREATE INDEX IF NOT EXISTS idx_messages_nickname "
           "ON messages(nickname)");

    q.exec("CREATE TABLE IF NOT EXISTS sessions ("
           "token      TEXT    PRIMARY KEY,"
           "nickname   TEXT    NOT NULL,"
           "created_at INTEGER NOT NULL"
           ")");

    q.exec("CREATE INDEX IF NOT EXISTS idx_sessions_nickname "
           "ON sessions(nickname)");

    qDebug() << "SQLite initialized";
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

    if (!m_pg.open()) {
        qWarning() << "PostgreSQL connection failed:" << m_pg.lastError().text();
        return false;
    }

    qDebug() << "PostgreSQL connected";
    return true;
}
