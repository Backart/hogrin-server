#ifndef CONFIG_H
#define CONFIG_H

#pragma once

namespace Config {
    constexpr int RELAY_MAX_BLOB_SIZE = 1 * 1024 * 1024; // 1 MB на сообщение
    constexpr int RELAY_MAX_QUEUE     = 100;             // maximum messages in queue
    constexpr int RELAY_MESSAGE_TTL_DAYS = 7;
    constexpr int RELAY_MAX_STORE_PER_IP = 200;
}

#endif // CONFIG_H
