#include <QTemporaryDir>
#include "../WiiQt/nandbin.h"
#include "../WiiQt/nandinstall.h"
#include "../WiiQt/nusdownloader.h"
#include "../WiiQt/tiktmd.h"
#include "../WiiQt/tools.h"
#include "../WiiQt/uidmap.h"

static void Require( bool ok, const char *message )
{
    if( !ok )
        qFatal( "%s", message );
}

static void Check( const QString &checker, const QString &path, const QStringList &flags, int expected )
{
    QProcess process;
    process.setProcessChannelMode( QProcess::MergedChannels );
    process.start( checker, QStringList() << path << flags );
    Require( process.waitForFinished( 120000 ), "Verifier did not finish" );
    if( process.exitStatus() != QProcess::NormalExit || process.exitCode() != expected )
    {
        qCritical().noquote() << process.readAll();
        qFatal( "Unexpected verifier exit status: %d (expected %d)", process.exitCode(), expected );
    }
}

//the typed lookups must describe the same filesystem as the item tree
static void CheckTypedLookups( NandBin &nand, NandItem *item, const QString &path )
{
    NandEntry entry;
    Require( nand.Stat( path, &entry ), "Stat missed an entry that is in the tree" );
    Require( entry.name == item->text( 0 ) && entry.index == item->text( 1 ).toUInt()
             && entry.size == item->text( 2 ).toUInt( NULL, 16 ) && entry.uid == item->text( 3 ).toUInt( NULL, 16 )
             && entry.IsDir() == ( item->text( 7 ).left( 2 ).toInt( NULL, 16 ) == NAND_DIR ),
             "Stat disagrees with the tree" );
    const QList<NandEntry> children = nand.Children( entry.index );
    Require( children.size() == item->childCount(), "Children disagrees with the tree" );
    for( int i = 0; i < children.size(); i++ )
    {
        Require( children.at( i ).name == item->child( i )->text( 0 ), "Children order differs from the tree" );
        CheckTypedLookups( nand, item->child( i ), ( path == "/" ? path : path + "/" ) + children.at( i ).name );
    }
}

//a title with 1 private and 1 shared content, encrypted like it comes from NUS
static NusJob MakeTitle( quint64 tid, const QByteArray &privateData, const QByteArray &sharedData )
{
    const QList<QByteArray> contents = QList<QByteArray>() << privateData << sharedData;
    QByteArray tmd( 0x1e4 + 0x24 * contents.size(), '\0' );
    qToBigEndian<quint32>( ES_SIG_RSA2048, reinterpret_cast<uchar *>( tmd.data() ) );
    qToBigEndian<quint64>( tid, reinterpret_cast<uchar *>( tmd.data() + 0x18c ) );
    qToBigEndian<quint16>( 3, reinterpret_cast<uchar *>( tmd.data() + 0x1dc ) );
    qToBigEndian<quint16>( contents.size(), reinterpret_cast<uchar *>( tmd.data() + 0x1de ) );
    for( int i = 0; i < contents.size(); i++ )
    {
        uchar *record = reinterpret_cast<uchar *>( tmd.data() + 0x1e4 + 0x24 * i );
        qToBigEndian<quint32>( 0x10 + i, record );
        //the index is not the position in the list, so decrypting with the wrong one fails the hash
        qToBigEndian<quint16>( 5 - i, record + 4 );
        qToBigEndian<quint16>( i ? 0x8001 : 1, record + 6 );
        qToBigEndian<quint64>( contents.at( i ).size(), record + 8 );
        memcpy( record + 16, GetSha1( contents.at( i ) ).constData(), 20 );
    }
    QByteArray ticket( 0x2a4, '\0' );
    qToBigEndian<quint32>( ES_SIG_RSA2048, reinterpret_cast<uchar *>( ticket.data() ) );
    qToBigEndian<quint64>( tid, reinterpret_cast<uchar *>( ticket.data() + 0x1dc ) );

    NusJob job;
    job.tid = tid;
    job.version = 3;
    job.decrypt = false;
    job.data << tmd << ticket;
    Ticket key( ticket, false );
    for( int i = 0; i < contents.size(); i++ )
    {
        AesSetKey( key.DecryptedKey() );
        job.data << AesEncrypt( 5 - i, PaddedByteArray( contents.at( i ), 0x40 ) );
    }
    return job;
}

static void CheckTitleInstall( const QString &path )
{
    const quint64 tid = 0x0001000154495431ull;
    const QString dir = "/title/00010001/54495431";
    const QByteArray privateData( 0x5000, 'p' );
    const QByteArray sharedData( 0x123, 's' );

    NandBin nand;
    Require( nand.CreateNew( path, QByteArray( 0x400, '\0' ), QByteArray( 0x108000, '\xff' ) ), "CreateNew failed" );
    Require( NandCreateDefaultEntries( nand ) && nand.Stat( "/sys/cert.sys" ) && nand.Stat( "/tmp" ), "Default entries failed" );
    Require( NandCreateIfNeeded( nand, "/tmp", 0, 0, NAND_DIR, NAND_RW, NAND_RW, NAND_RW ) != 0
             && nand.Children( 0 ).size() == 8, "CreateIfNeeded duplicated an entry" );

    UIDmap uid;
    SharedContentMap shared;
    NusJob job = MakeTitle( tid, privateData, sharedData );

    NusJob bad = job;
    bad.data[ 2 ][ 0 ] = bad.data.at( 2 ).at( 0 ) ^ 1;
    Require( !DecryptAndVerifyTitle( bad ) && !NandInstallTitle( nand, uid, shared, bad ), "Corrupt content was accepted" );
    bad = job;
    bad.data[ 0 ].truncate( 0x1e4 );
    Require( !DecryptAndVerifyTitle( bad ), "Truncated tmd was accepted" );
    bad = job;
    bad.version = 4;
    Require( !DecryptAndVerifyTitle( bad ), "Wrong version was accepted" );
    Require( !nand.Stat( dir ) && shared.Data().isEmpty(), "A rejected title changed the nand" );

    bool deleted = true;
    Require( NandInstallTitle( nand, uid, shared, job, &deleted ) && !deleted, "Install failed" );
    NandEntry entry;
    Require( nand.Stat( dir + "/data", &entry ) && entry.IsDir() && entry.uid == uid.GetUid( tid, false ), "Data folder is wrong" );
    Require( nand.GetData( dir + "/content/00000010.app" ) == privateData, "Private content is wrong" );
    Require( shared.GetAppFromHash( GetSha1( sharedData ) ) == "00000000"
             && nand.GetData( "/shared1/00000000.app" ) == sharedData, "Shared content is wrong" );
    Require( nand.GetData( dir + "/content/title.tmd" ) == job.data.at( 0 )
             && nand.GetData( "/ticket/00010001/54495431.tik" ) == job.data.at( 1 ), "Tmd or ticket is wrong" );

    //installing again replaces the private files and reuses the shared one
    Require( NandInstallTitle( nand, uid, shared, job, &deleted ) && deleted, "Reinstall failed" );
    Require( nand.Children( entry.index ).isEmpty() && !nand.Stat( "/shared1/00000001.app" ), "Reinstall duplicated content" );
    Require( nand.WriteMetaData(), "Write metadata failed" );
}

//a title that is completely in the cache is returned without touching the network
static void CheckOfflineCache( const QString &cache )
{
    const quint64 tid = 0x0001000154495431ull;
    const QByteArray privateData( 0x5000, 'p' );
    const QByteArray sharedData( 0x123, 's' );
    const NusJob title = MakeTitle( tid, privateData, sharedData );
    const QString dir = cache + "/00010001/54495431/v3/";
    auto save = [ & ]( const QString &name, const QByteArray &stuff ) {
        QFile file( dir + name );
        Require( file.open( QIODevice::WriteOnly ) && file.write( stuff ) == stuff.size(), "Could not fill the cache" );
    };
    Require( QDir().mkpath( dir ), "Could not create the cache" );
    save( "tmd.3", title.data.at( 0 ) );
    save( "cetk", title.data.at( 1 ) );
    save( "00000010", title.data.at( 2 ) );

    NusJob job;
    job.tid = tid;
    job.version = 3;
    job.decrypt = true;
    QString error;
    {
        //the second content is not there
        NusDownloader nus( NULL, cache );
        nus.SetOffline();
        Require( !NusGetTitleBlocking( nus, job, &error ) && error.contains( "Offline mode" ), "Offline mode tried to download" );
    }
    save( "00000011", title.data.at( 3 ) );
    {
        NusDownloader nus( NULL, cache );
        nus.SetOffline();
        Require( NusGetTitleBlocking( nus, job, &error ), "A cached title was not returned" );
        Require( job.data.size() == 4 && job.data.at( 0 ) == title.data.at( 0 ) && job.data.at( 1 ) == title.data.at( 1 )
                 && job.data.at( 2 ) == privateData && job.data.at( 3 ) == sharedData, "The cached title is wrong" );
    }
    job.data.clear();
    {
        //the synthetic title is not signed
        NusDownloader nus( NULL, cache );
        nus.SetOffline();
        nus.SetRequireSignatures();
        Require( !NusGetTitleBlocking( nus, job, &error ) && error.contains( "not signed" ), "An unsigned TMD was accepted" );
    }
    job.version = 4;
    {
        NusDownloader nus( NULL, cache );
        nus.SetOffline();
        Require( !NusGetTitleBlocking( nus, job, &error ), "A title that is not cached was returned" );
    }
}

static void FlipByte( const QString &path, qint64 offset )
{
    QFile file( path );
    Require( file.open( QIODevice::ReadWrite ) && file.seek( offset ), "Open for corruption failed" );
    QByteArray byte = file.read( 1 );
    Require( byte.size() == 1 && file.seek( offset ), "Read failed" );
    byte[ 0 ] = byte.at( 0 ) ^ 1;
    Require( file.write( byte ) == 1, "Write corruption failed" );
}

int main( int argc, char **argv )
{
    QCoreApplication app( argc, argv );
    Require( argc == 2, "Pass the nandBinCheck executable" );
    const QString checker = QFileInfo( app.arguments().at( 1 ) ).absoluteFilePath();
    QTemporaryDir directory;
    Require( directory.isValid(), "Could not create temporary directory" );
    CheckTitleInstall( directory.filePath( "install.bin" ) );
    CheckOfflineCache( directory.filePath( "cache" ) );
    const QString path = directory.filePath( "synthetic.bin" );
    const QByteArray content( "original synthetic content" );
    const QString titlePath = "/title/00010001/54455354/content/00000000.app";
    const quint64 tid = 0x0001000154455354ull;
    {
        NandBin nand;
        Require( nand.CreateNew( path, QByteArray( 0x400, '\0' ), QByteArray( 0x108000, '\xff' ) ), "CreateNew failed" );
        auto entry = [&]( const QString &name, quint32 uid, quint16 gid, quint8 attr ) {
            quint16 handle = nand.CreateEntry( name, uid, gid, attr, NAND_RW, NAND_RW, 0 );
            Require( handle != 0, "CreateEntry failed" );
            return handle;
        };
        entry( "/sys", 0, 0, NAND_DIR );
        UIDmap uid;
        Require( uid.GetUid( tid ) == 0x1001, "Unexpected test title uid" );
        Require( nand.SetData( entry( "/sys/uid.sys", 0, 0, NAND_FILE ), uid.Data() ), "Write uid map failed" );
        entry( "/shared1", 0, 0, NAND_DIR );
        Require( nand.SetData( entry( "/shared1/00000000.app", 0, 0, NAND_FILE ), content ), "Write shared data failed" );
        Require( nand.SetData( entry( "/shared1/content.map", 0, 0, NAND_FILE ), QByteArray( "00000000" ) + GetSha1( content ) ), "Write shared map failed" );
        entry( "/ticket", 0, 0, NAND_DIR );
        entry( "/ticket/00010001", 0, 0, NAND_DIR );
        QByteArray ticket( 0x2a4, '\0' );
        qToBigEndian<quint32>( ES_SIG_RSA2048, reinterpret_cast<uchar *>( ticket.data() ) );
        qToBigEndian<quint64>( tid, reinterpret_cast<uchar *>( ticket.data() + 0x1dc ) );
        Require( nand.SetData( entry( "/ticket/00010001/54455354.tik", 0, 0, NAND_FILE ), ticket ), "Write ticket failed" );
        entry( "/title", 0, 0, NAND_DIR );
        entry( "/title/00010001", 0, 0, NAND_DIR );
        entry( "/title/00010001/54455354", 0, 0, NAND_DIR );
        entry( "/title/00010001/54455354/content", 0, 0, NAND_DIR );
        QByteArray tmdData( 0x208, '\0' );
        qToBigEndian<quint32>( ES_SIG_RSA2048, reinterpret_cast<uchar *>( tmdData.data() ) );
        qToBigEndian<quint64>( tid, reinterpret_cast<uchar *>( tmdData.data() + 0x18c ) );
        qToBigEndian<quint16>( 1, reinterpret_cast<uchar *>( tmdData.data() + 0x1de ) );
        qToBigEndian<quint16>( 1, reinterpret_cast<uchar *>( tmdData.data() + 0x1ea ) );
        qToBigEndian<quint64>( content.size(), reinterpret_cast<uchar *>( tmdData.data() + 0x1ec ) );
        tmdData.replace( 0x1f4, 20, GetSha1( content ) );
        Require( nand.SetData( entry( "/title/00010001/54455354/content/title.tmd", 0, 0, NAND_FILE ), tmdData ), "Write TMD failed" );
        Require( nand.SetData( entry( titlePath, 0, 0, NAND_FILE ), content ), "Write title content failed" );
        Require( nand.WriteMetaData(), "Write metadata failed" );

        NandItem *tree = nand.GetTree();
        CheckTypedLookups( nand, tree->child( 0 ), "/" );
        delete tree;
        NandEntry file;
        Require( nand.Stat( titlePath, &file ) && file.IsFile() && file.size == quint32( content.size() ), "Stat of a file failed" );
        Require( !nand.Stat( "/title/missing" ) && !nand.Stat( "title" ) && !nand.Stat( "/title//00010001" ), "Stat accepted a bad path" );
        Require( nand.Children( file.index ).isEmpty(), "A file has no children" );
    }
    // No Nintendo code or real keys: this fixture tests integrity, not bootability.
    Check( checker, path, { "-spare" }, 0 );
    Check( checker, path, { "-fs" }, 0 );
    {
        NandBin nand;
        Require( nand.SetPath( path ) && nand.InitNand(), "Reopen failed" );
        Require( nand.SetData( titlePath, QByteArray( "changed synthetic content" ) ) && nand.WriteMetaData(), "Change content failed" );
    }
    // Valid ECC/HMAC does not excuse a mismatch against the title's original hash.
    Check( checker, path, { "-spare" }, 0 );
    Check( checker, path, { "-fs" }, 1 );
    Check( checker, path, { "-fs", "-continue" }, 1 );
    // Corrupt only an older superblock's HMAC, leaving its data/ECC and active FS intact.
    const qint64 hmacOffset = ( ( 0x7f00 + 15 ) * 8 + 6 ) * 0x840 + 0x801;
    FlipByte( path, hmacOffset );
    Check( checker, path, { "-spare" }, 1 );
    Check( checker, path, { "-spare", "-continue" }, 1 );
    FlipByte( path, hmacOffset );
    // Independently corrupt ECC, which is outside the HMAC-protected page data.
    FlipByte( path, 0x7f00 * 8 * 0x840 + 0x830 );
    Check( checker, path, { "-spare" }, 1 );
    Check( checker, path, { "-spare", "-continue" }, 1 );
    qInfo() << "Integrity exit-status regressions passed";
}
