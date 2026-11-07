# Read-only NAND support, shared by the inspector and external tools.
QT += core gui widgets
CONFIG += c++17 sdk_no_version_check
INCLUDEPATH += $$PWD
SOURCES += $$PWD/nandbin.cpp \
    $$PWD/blocks0to7.cpp \
    $$PWD/nandspare.cpp \
    $$PWD/tools.cpp \
    $$PWD/tiktmd.cpp \
    $$PWD/uidmap.cpp \
    $$PWD/aes.c \
    $$PWD/sha1.c
HEADERS += $$PWD/nandbin.h
