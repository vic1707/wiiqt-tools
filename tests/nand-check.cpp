#include "../WiiQt/nandbin.h"
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
