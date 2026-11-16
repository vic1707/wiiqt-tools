#ifndef NANDINSTALL_H
#define NANDINSTALL_H

#include "nandbin.h"
#include "sharedcontentmap.h"
#include "tools.h"
#include "uidmap.h"

//functions for building up the contents of a nand.bin.  none of these call WriteMetaData(),
//that is left up to you once all your changes are done

//create an entry if it doesnt already exist
//returns the index of the entry, or 0 on error
quint16 NandCreateIfNeeded( NandBin &nand, const QString &path, quint32 uid, quint16 gid, quint8 attr, quint8 user_perm, quint8 group_perm, quint8 other_perm );

//create the folders that every nand has in its root, and /sys/cert.sys
//expects a nand that only has a root entry
bool NandCreateDefaultEntries( NandBin &nand );

//install a title: creates its folders, replaces any old tmd and private contents, and writes the ticket, tmd and contents
//every content is decrypted ( if needed ) and checked against the tmd before anything is written
//the ticket is written as it was given, it is never fakesigned
//uid and shared are updated to match what was installed, but not written to the nand
//deletedOld, if given, is set to true when old files were removed from the title's content folder
bool NandInstallTitle( NandBin &nand, UIDmap &uid, SharedContentMap &shared, NusJob job, bool *deletedOld = NULL );

#endif // NANDINSTALL_H
