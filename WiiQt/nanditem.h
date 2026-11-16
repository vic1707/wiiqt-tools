#ifndef NANDITEM_H
#define NANDITEM_H

#include <QList>
#include <QStringList>

//one entry of the nand's file tree, with the same columns the GUIs show:
//name, entry #, size, uid, gid, x3, mode, attr
//it mimics the part of QTreeWidgetItem that NandBin uses, so the nand code needs no widgets.
//use nanditemwidget.h to turn a tree of these into QTreeWidgetItems
class NandItem
{
public:
    explicit NandItem( const QStringList &text ) : columns( text ), par( NULL ) {}
    NandItem( NandItem *parent, const QStringList &text ) : columns( text ), par( parent )
    {
        if( par )
            par->children << this;
    }
    ~NandItem()
    {
        if( par )
            par->children.removeOne( this );
        while( !children.isEmpty() )
        {
            NandItem *c = children.takeLast();
            c->par = NULL;
            delete c;
        }
    }

    QString text( int column ) const { return columns.value( column ); }
    void setText( int column, const QString &text )
    {
        while( columns.size() <= column )
            columns << QString();
        columns[ column ] = text;
    }

    NandItem *parent() const { return par; }
    int childCount() const { return children.size(); }
    NandItem *child( int i ) const { return children.value( i, NULL ); }
    NandItem *takeChild( int i )
    {
        if( i < 0 || i >= children.size() )
            return NULL;
        NandItem *c = children.takeAt( i );
        c->par = NULL;
        return c;
    }

    //deep copy, owned by the caller
    NandItem *clone() const
    {
        NandItem *ret = new NandItem( columns );
        foreach( NandItem *c, children )
        {
            NandItem *copy = c->clone();
            copy->par = ret;
            ret->children << copy;
        }
        return ret;
    }

private:
    Q_DISABLE_COPY( NandItem )
    QStringList columns;
    NandItem *par;
    QList< NandItem * > children;
};

#endif // NANDITEM_H
