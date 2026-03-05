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
    QString pubkey;   // hex publick key
};

class Bootstrap_Server : public QObject {
    Q_OBJECT
public:
    explicit Bootstrap_Server(quint16 port, QObject *parent = nullptr);
    bool start();

private slots:
    void handle_new_connection();
    void handle_data(QTcpSocket *socket, const QByteArray &data);

private:
    QTcpServer *m_server;
    quint16     m_port;

    void    send_response(QTcpSocket *socket, const QString &response);
    QString normalize_address(const QString &address);

    QTimer *m_cleanup_timer;
    void cleanup_old_messages();

    QMap<QString, int> m_ip_store_count; // ip -> count STORE for sessia
    void reset_ip_counters();            // reset counters

    QTimer *m_ip_reset_timer;

    QSqlDatabase m_db;
    bool init_database();
};

#endif // BOOTSTRAP_SERVER_H
