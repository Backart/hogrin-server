#ifndef BOOTSTRAP_SERVER_H
#define BOOTSTRAP_SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QMap>

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
    quint16 m_port;
    // nickname -> host:port
    QMap<QString, QString> m_peers;

    void send_response(QTcpSocket *socket, const QString &response);

    QString normalize_address(const QString &address);
};

#endif // BOOTSTRAP_SERVER_H
