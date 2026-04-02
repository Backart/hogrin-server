#ifndef BOOTSTRAP_SERVER_H
#define BOOTSTRAP_SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QWebSocketServer>
#include <QWebSocket>
#include <QNetworkRequest>
#include <QMap>
#include <QDateTime>
#include <QTimer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <functional>

#include <QDebug>
#include <QUuid>
#include <sodium.h>

#include "config.h"

class Bootstrap_Server : public QObject {
    Q_OBJECT
public:
    explicit Bootstrap_Server(quint16 port, QObject *parent = nullptr);
    bool start();

private slots:
    void handle_new_connection();
    void handle_new_ws_connection();

private:
    QTcpServer *m_server;
    QWebSocketServer *m_ws_server;
    quint16 m_port;

    QMap<QTcpSocket*, QByteArray> m_buffers;
    QMap<QString, int> m_ip_store_count;

    QSqlDatabase m_db;
    QSqlDatabase m_pg;

    QTimer *m_cleanup_timer;
    QTimer *m_ip_reset_timer;

    // --- Транспорты ---
    void handle_incoming_data(QTcpSocket *socket);
    void handle_data(QTcpSocket *socket, const QString &msg);
    void handle_ws_data(QWebSocket *socket, const QString &ip, const QString &msg);
    void send_response(QTcpSocket *socket, const QString &response);

    // --- Ядро логики ---
    void core_process_message(const QString &ip, const QString &msg, std::function<void(const QString&)> reply);

    // --- Авторизация ---
    void handle_auth_register(const QString &nickname, const QString &password, std::function<void(const QString&)> reply);
    void handle_auth_login(const QString &nickname, const QString &password, std::function<void(const QString&)> reply);
    void handle_auth_verify(const QString &token, std::function<void(const QString&)> reply);
    void handle_auth_logout(const QString &token, std::function<void(const QString&)> reply);

    // --- Утилиты ---
    QString normalize_address(const QString &address);
    void cleanup_old_messages();
    void reset_ip_counters();
    bool init_database();
    bool init_postgres();
};

#endif // BOOTSTRAP_SERVER_H