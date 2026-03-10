#ifndef BOOTSTRAP_SERVER_H
#define BOOTSTRAP_SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QMap>
#include <QDateTime>
#include <QList>
#include <QTimer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

#include "config.h"

struct Stored_Message {
    QByteArray data;
    QDateTime  stored_at;
};

struct Peer_Info {
    QString address;  // host|port
    QString pubkey;   // hex public key
};

class Bootstrap_Server : public QObject {
    Q_OBJECT
public:
    explicit Bootstrap_Server(quint16 port, QObject *parent = nullptr);
    bool start();

private slots:
    void handle_new_connection();

    void handle_data(QTcpSocket *socket, const QString &line);

private:
    QTcpServer *m_server;
    quint16     m_port;

    void    send_response(QTcpSocket *socket, const QString &response);
    QString normalize_address(const QString &address);

    QMap<QTcpSocket*, QByteArray> m_buffers;
    void handle_incoming_data(QTcpSocket *socket);

    // Cleanup
    QTimer *m_cleanup_timer;
    void cleanup_old_messages();

    // Rate limiting
    QMap<QString, int> m_ip_store_count;
    void reset_ip_counters();
    QTimer *m_ip_reset_timer;

    // SQLite — peers, messages, sessions
    QSqlDatabase m_db;
    bool init_database();

    // PostgreSQL — users
    QSqlDatabase m_pg;
    bool init_postgres();

    // AUTH handlers
    void handle_auth_register(QTcpSocket *socket, const QString &nickname, const QString &password);
    void handle_auth_login   (QTcpSocket *socket, const QString &nickname, const QString &password);
    void handle_auth_verify  (QTcpSocket *socket, const QString &token);
    void handle_auth_logout  (QTcpSocket *socket, const QString &token);
};

#endif // BOOTSTRAP_SERVER_H
