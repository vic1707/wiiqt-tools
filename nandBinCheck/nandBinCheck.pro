#-------------------------------------------------
#
# Project created by QtCreator 2010-12-17T16:22:53
#
#-------------------------------------------------

#QT       += core\
#	    gui

TARGET = nandBinCheck
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

QT += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

include(../WiiQt/nand.pri)

SOURCES += main.cpp \
    ../WiiQt/sharedcontentmap.cpp \
    ../WiiQt/settingtxtdialog.cpp \
    ../WiiQt/u8.cpp \
    ../WiiQt/lz77.cpp \
    ../WiiQt/ash.cpp

HEADERS += ../WiiQt/tiktmd.h \
    ../WiiQt/nandbin.h \
    ../WiiQt/tools.h \
    ../WiiQt/blocks0to7.h \
    ../WiiQt/uidmap.h \
    ../WiiQt/sharedcontentmap.h \
    ../WiiQt/nandspare.h \
    ../WiiQt/settingtxtdialog.h \
    ../WiiQt/u8.h \
    ../WiiQt/lz77.h \
    ../WiiQt/ash.h

FORMS += \
    ../WiiQt/settingtxtdialog.ui

macx: QMAKE_APPLE_DEVICE_ARCHS = arm64
