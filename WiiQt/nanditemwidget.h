#ifndef NANDITEMWIDGET_H
#define NANDITEMWIDGET_H

#include "nanditem.h"

#include <QFont>
#include <QIcon>
#include <QTreeWidgetItem>

//for GUIs: build the QTreeWidgetItem tree for a NandItem tree ( NandBin::GetTree() ).
//the caller owns the result.  files get the "files" icon and everything else gets "dirs"
inline QTreeWidgetItem *NandItemToTreeWidgetItem( const NandItem *item, const QIcon &dirs = QIcon(), const QIcon &files = QIcon(), bool isRoot = true )
{
    if( !item )
        return NULL;
    QStringList text;
    for( int i = 0; i < 8; i++ )
        text << item->text( i );
    while( text.size() > 1 && text.last().isEmpty() )
        text.removeLast();

    QTreeWidgetItem *ret = new QTreeWidgetItem( text );
    if( !isRoot )
    {
        for( int i = 1; i < 7; i++ )
            ret->setTextAlignment( i, Qt::AlignRight | Qt::AlignVCenter );
        ret->setFont( 7, QFont( "Courier New", 10, 5 ) );
        ret->setIcon( 0, item->text( 7 ).startsWith( "01" ) ? files : dirs );
    }
    int cnt = item->childCount();
    for( int i = 0; i < cnt; i++ )
        ret->addChild( NandItemToTreeWidgetItem( item->child( i ), dirs, files, false ) );
    return ret;
}

#endif // NANDITEMWIDGET_H
