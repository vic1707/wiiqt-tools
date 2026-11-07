QT += core gui widgets
CONFIG += console c++17
CONFIG -= app_bundle
DEFINES += NAND_BIN_CAN_WRITE
TARGET = nand-check-test
SOURCES += nand-check.cpp \
    ../WiiQt/nandbin.cpp \
    ../WiiQt/blocks0to7.cpp \
    ../WiiQt/nandspare.cpp \
    ../WiiQt/tools.cpp \
    ../WiiQt/tiktmd.cpp \
    ../WiiQt/uidmap.cpp \
    ../WiiQt/aes.c \
    ../WiiQt/sha1.c
HEADERS += ../WiiQt/nandbin.h
