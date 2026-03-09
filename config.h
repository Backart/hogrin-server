#ifndef CONFIG_H
#define CONFIG_H

#pragma once

#include <QString>
#include <QProcessEnvironment>

namespace Config {
// Relay limits
constexpr int RELAY_MAX_BLOB_SIZE    = 1 * 1024 * 1024;
constexpr int RELAY_MAX_QUEUE        = 100;
constexpr int RELAY_MESSAGE_TTL_DAYS = 7;
constexpr int RELAY_MAX_STORE_PER_IP = 200;

inline QString db_host()     { return QProcessEnvironment::systemEnvironment().value("HOGRIN_DB_HOST",     "localhost"); }
inline int     db_port()     { return QProcessEnvironment::systemEnvironment().value("HOGRIN_DB_PORT",     "5432").toInt(); }
inline QString db_name()     { return QProcessEnvironment::systemEnvironment().value("HOGRIN_DB_NAME",     "hogrin"); }
inline QString db_user()     { return QProcessEnvironment::systemEnvironment().value("HOGRIN_DB_USER",     "hogrin_admin"); }
inline QString db_password() { return QProcessEnvironment::systemEnvironment().value("HOGRIN_DB_PASSWORD", ""); }
}

#endif // CONFIG_H
