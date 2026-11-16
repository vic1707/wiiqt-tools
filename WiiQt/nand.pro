# NAND library for external tools: read, create and edit nand.bin, fetch titles from NUS.
TEMPLATE = lib
CONFIG += staticlib
TARGET = wiiqt-nand
QT += network
QT -= gui
DEFINES += NAND_BIN_CAN_WRITE
include(nand.pri)
SOURCES += $$PWD/sharedcontentmap.cpp \
    $$PWD/nandinstall.cpp \
    $$PWD/nusdownloader.cpp
HEADERS += $$PWD/nusdownloader.h
