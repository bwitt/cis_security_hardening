#!/bin/bash

ps -eZ | awk '$1 ~ /unconfined_service_t/'

exit 0
