#include <QCoreApplication>
#include <QDebug>
#include "bootstrap_server.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    qDebug() << "Starting bootstrap server...";
    Bootstrap_Server server(47832);
    if (!server.start())
        return 1;
    qDebug() << "Server running.";
    return a.exec();
}
