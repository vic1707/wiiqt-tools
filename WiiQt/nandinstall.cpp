#include "nandinstall.h"
#include "tiktmd.h"

quint16 NandCreateIfNeeded( NandBin &nand, const QString &path, quint32 uid, quint16 gid, quint8 attr, quint8 user_perm, quint8 group_perm, quint8 other_perm )
{
    NandEntry entry;
    //TODO - if the item already exists, check that its attributes match the expected ones
    if( nand.Stat( path, &entry ) )
        return entry.index;
    return nand.CreateEntry( path, uid, gid, attr, user_perm, group_perm, other_perm );
}

bool NandCreateDefaultEntries( NandBin &nand )
{
    if( !nand.CreateEntry( "/sys", 0, 0, NAND_DIR, NAND_RW, NAND_RW, 0 )
        || !nand.CreateEntry( "/ticket", 0, 0, NAND_DIR, NAND_RW, NAND_RW, 0 )
        || !nand.CreateEntry( "/title", 0, 0, NAND_DIR, NAND_RW, NAND_RW, NAND_READ )
        || !nand.CreateEntry( "/shared1", 0, 0, NAND_DIR, NAND_RW, NAND_RW, 0 )
        || !nand.CreateEntry( "/shared2", 0, 0, NAND_DIR, NAND_RW, NAND_RW, NAND_RW )
        || !nand.CreateEntry( "/import", 0, 0, NAND_DIR, NAND_RW, NAND_RW, 0 )
        || !nand.CreateEntry( "/meta", 0x1000, 1, NAND_DIR, NAND_RW, NAND_RW, NAND_RW )
        || !nand.CreateEntry( "/tmp", 0, 0, NAND_DIR, NAND_RW, NAND_RW, NAND_RW ) )
    {
        qWarning() << "NandCreateDefaultEntries -> error creating directories";
        return false;
    }
    //add cert.sys
    quint16 handle = nand.CreateEntry( "/sys/cert.sys", 0, 0, NAND_FILE, NAND_RW, NAND_RW, NAND_READ );
    if( !handle || !nand.SetData( handle, QByteArray( (const char*)&certs_dat, CERTS_DAT_SIZE ) ) )
    {
        qWarning() << "NandCreateDefaultEntries -> error creating cert.sys";
        return false;
    }
    return true;
}

static bool WriteFile( NandBin &nand, const QString &path, const QByteArray &stuff )
{
    quint16 r = NandCreateIfNeeded( nand, path, 0, 0, NAND_FILE, NAND_RW, NAND_RW, 0 );
    if( !r || !nand.SetData( r, stuff ) )
    {
        qWarning() << "NandInstallTitle -> can't write" << path;
        return false;
    }
    return true;
}

bool NandInstallTitle( NandBin &nand, UIDmap &uid, SharedContentMap &shared, NusJob job, bool *deletedOld )
{
    if( deletedOld )
        *deletedOld = false;

    //after this, the job holds decrypted contents that match the tmd
    if( !DecryptAndVerifyTitle( job ) )
    {
        qWarning() << "NandInstallTitle -> bad title data";
        return false;
    }
    Tmd t( job.data.at( 0 ) );
    Ticket ticket( job.data.at( 1 ), false );

    QString tid = QString( "%1" ).arg( job.tid, 16, 16, QChar( '0' ) );
    QString upper = tid.left( 8 );
    QString lower = tid.right( 8 );
    QString titleDir = "/title/" + upper + "/" + lower;

    quint32 _uid = uid.GetUid( job.tid );
    if( !_uid )
    {
        qWarning() << "NandInstallTitle -> no uid";
        return false;
    }

    //create all the folders
    if( !NandCreateIfNeeded( nand, "/ticket/" + upper, 0, 0, NAND_DIR, NAND_RW, NAND_RW, 0 )
        || !NandCreateIfNeeded( nand, "/title/" + upper, 0, 0, NAND_DIR, NAND_RW, NAND_RW, NAND_READ )
        || !NandCreateIfNeeded( nand, titleDir, 0, 0, NAND_DIR, NAND_RW, NAND_RW, NAND_READ )
        || !NandCreateIfNeeded( nand, titleDir + "/data", _uid, t.Gid(), NAND_DIR, NAND_RW, 0, 0 )
        || !NandCreateIfNeeded( nand, titleDir + "/content", 0, 0, NAND_DIR, NAND_RW, NAND_RW, 0 ) )
    {
        qWarning() << "NandInstallTitle -> can't create folders for" << tid;
        return false;
    }

    //delete old tmd/.apps and whatever else in the content folder
    NandEntry content;
    if( !nand.Stat( titleDir + "/content", &content ) )
        return false;
    const QList<NandEntry> old = nand.Children( content.index );
    for( const NandEntry &entry : old )
    {
        if( !nand.Delete( titleDir + "/content/" + entry.name ) )
        {
            qWarning() << "NandInstallTitle -> error deleting old title";
            return false;
        }
        if( deletedOld )
            *deletedOld = true;
    }

    if( !WriteFile( nand, "/ticket/" + upper + "/" + lower + ".tik", ticket.Data() )
        || !WriteFile( nand, titleDir + "/content/title.tmd", t.Data() ) )
        return false;

    quint16 cnt = t.Count();
    for( quint16 i = 0; i < cnt; i++ )
    {
        const QByteArray &decData = job.data.at( i + 2 );
        if( t.Type( i ) == 1 )//private
        {
            if( !WriteFile( nand, titleDir + "/content/" + t.Cid( i ) + ".app", decData ) )
                return false;
        }
        else//shared.  DecryptAndVerifyTitle() only lets these 2 types through
        {
            if( !shared.GetAppFromHash( t.Hash( i ) ).isEmpty() )//this one is already installed
                continue;

            //get next available cid in the shared map
            QString cid = shared.GetNextEmptyCid();
            if( !WriteFile( nand, "/shared1/" + cid + ".app", decData ) )
                return false;
            shared.AddEntry( cid, t.Hash( i ) );
        }
    }
    return true;
}
