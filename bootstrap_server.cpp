#include "bootstrap_server.h"
#include <QDebug>

Bootstrap_Server::Bootstrap_Server(quint16 port, QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_port(port)
    , m_cleanup_timer(new QTimer(this))
    , m_ip_reset_timer(new QTimer(this))
{
    if (!init_database())
        qWarning() << "Database init failed!";

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
    connect(m_server, &QTcpServer::newConnection, this, &Bootstrap_Server::handle_new_connection);
    qDebug() << "Bootstrap server started on port" << m_port;
    return true;
}

void Bootstrap_Server::handle_new_connection()
{
    while (m_server->hasPendingConnections()) {
        QTcpSocket *socket = m_server->nextPendingConnection();
        qDebug() << "New connection from:" << socket->peerAddress().toString();

        connect(socket, &QTcpSocket::readyRead, this, [this, socket](){
            handle_data(socket, socket->readAll());
        });

        connect(socket, &QTcpSocket::disconnected, this, [socket](){
            qDebug() << "Client disconnected:" << socket->peerAddress().toString();
            socket->deleteLater();
        });
    }
}

void Bootstrap_Server::handle_data(QTcpSocket *socket, const QByteArray &data)
{
    QString msg = QString::fromUtf8(data).trimmed();
    qDebug() << "Received:" << msg;

    if (msg.startsWith("REGISTER:")) {
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
            QString address = q.value(0).toString();
            QString pubkey  = q.value(1).toString();
            send_response(socket, "FOUND:" + address + "|" + pubkey);
        } else {
            send_response(socket, "NOT_FOUND");
        }
    }
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

        if (blob.isEmpty()) { send_response(socket, "ERROR:EMPTY_BLOB"); return; }
        if (blob.size() > Config::RELAY_MAX_BLOB_SIZE) { send_response(socket, "ERROR:TOO_LARGE"); return; }

        QSqlQuery count_q(m_db);
        count_q.prepare("SELECT COUNT(*) FROM messages WHERE nickname = :nick");
        count_q.bindValue(":nick", nickname);
        count_q.exec();
        count_q.next();
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
        q.prepare("SELECT id, blob FROM messages WHERE nickname = :nick ORDER BY id ASC");
        q.bindValue(":nick", nickname);
        q.exec();

        QStringList responses;
        QList<int> ids;

        while (q.next()) {
            ids << q.value(0).toInt();
            responses << "MSG:" + QString::fromUtf8(q.value(1).toByteArray().toHex());
        }

        if (responses.isEmpty()) {
            send_response(socket, "EMPTY");
            return;
        }
        QSqlQuery del(m_db);
        del.prepare("DELETE FROM messages WHERE nickname = :nick");
        del.bindValue(":nick", nickname);
        del.exec();

        send_response(socket, responses.join("\n"));
        qDebug() << "Fetched" << responses.size() << "messages for:" << nickname;
    }
    else if (msg.startsWith("UNREGISTER:")) {
        QString nickname = msg.mid(11);

        QSqlQuery q(m_db);
        q.prepare("DELETE FROM peers WHERE nickname = :nick");
        q.bindValue(":nick", nickname);

        if (q.exec() && q.numRowsAffected() > 0) {
            send_response(socket, "OK");
            qDebug() << "Unregistered:" << nickname;
        } else {
            send_response(socket, "NOT_FOUND");
        }
    }
}

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
        qWarning() << "Failed to open database:" << m_db.lastError().text();
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
           "stored_at INTEGER NOT NULL"  // unix timestamp
           ")");

    q.exec("CREATE INDEX IF NOT EXISTS idx_messages_nickname "
           "ON messages(nickname)");

    qDebug() << "Database initialized";
    return true;
}
