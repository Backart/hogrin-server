#include "bootstrap_server.h"
#include <QDebug>

Bootstrap_Server::Bootstrap_Server(quint16 port, QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_port(port)
{}

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
        if (parts.size() == 3) {
            QString nickname = parts[1];
            QString port     = parts[2];
            QString ip       = normalize_address(socket->peerAddress().toString()); // фикс
            QString address  = ip + "|" + port;
            m_peers[nickname] = address;
            qDebug() << "Registered:" << nickname << "->" << address;
            send_response(socket, "OK");
        }
    }
    else if (msg.startsWith("UNREGISTER:")) {
        QString nickname = msg.mid(11);
        if (m_peers.contains(nickname)) {
            m_peers.remove(nickname);
            qDebug() << "Unregistered:" << nickname;
            send_response(socket, "OK");
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
