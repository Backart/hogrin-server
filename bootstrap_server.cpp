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

    // Формат регистрации: REGISTER:nickname:port
    if (msg.startsWith("REGISTER:")) {
        QStringList parts = msg.split(":");
        if (parts.size() == 3) {
            QString nickname = parts[1];
            QString port     = parts[2];
            QString address  = socket->peerAddress().toString() + ":" + port;
            m_peers[nickname] = address;
            qDebug() << "Registered:" << nickname << "->" << address;
            send_response(socket, "OK");
        }
    }
    // Формат поиска: FIND:nickname
    else if (msg.startsWith("FIND:")) {
        QString nickname = msg.mid(5);
        if (m_peers.contains(nickname)) {
            send_response(socket, "FOUND:" + m_peers[nickname]);
        } else {
            send_response(socket, "NOT_FOUND");
        }
    }
}

void Bootstrap_Server::send_response(QTcpSocket *socket, const QString &response)
{
    socket->write((response + "\n").toUtf8());
}
