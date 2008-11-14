#ifndef AEKAVD_POSIXISTREAM_H
#define AEKAVD_POSIXISTREAM_H

#include <sdkunix/istream.h>

class posixIStream : public IStream
{
    int _fd;

public:

    posixIStream(int fd)
    {
        _fd = fd;
    }

    // IUnknown Interface

    virtual HRESULT QueryInterface(REFIID iid, void ** ppvObject)
    {
        return E_NOTIMPL;
    }

    virtual unsigned long AddRef(void)
    {
        return 0;
    }

    virtual unsigned long Release(void)
    {
        return 0;
    }

    // ISequentialStream Interface

    virtual HRESULT Read(/*[out]*/ void *pv, /*[in]*/ unsigned long cb, /*[out]*/ unsigned long *pcbRead)
    {
        if(!pv || !pcbRead)
            return STG_E_INVALIDPOINTER;

        ssize_t size;
        if((size = read(_fd, pv, cb)) == -1) {
            *pcbRead = 0;
            return STG_E_SEEKERROR;
        }
        *pcbRead = size;
        if(*pcbRead < cb)
            return S_FALSE;
        return S_OK;
    }

    virtual HRESULT Write(/*[in]*/ void const *pv, /*[in]*/ unsigned long cb, /*[out]*/  unsigned long *pcbWritten)
    {
        return E_NOTIMPL;
    }

    // IStream Interface

    virtual HRESULT Seek(/*[in]*/ LARGE_INTEGER dlibMove, /*[in]*/ unsigned long dwOrigin, /*[out]*/  ULARGE_INTEGER *plibNewPosition)
    {

        if(!plibNewPosition)
            return STG_E_INVALIDPOINTER;

        int whence;
        off64_t move, newPosition;

        switch(dwOrigin)
        {
        case STREAM_SEEK_SET:
            whence = SEEK_SET;
            break;
        case STREAM_SEEK_CUR:
            whence = SEEK_CUR;
            break;
        case STREAM_SEEK_END:
            whence = SEEK_END;
            break;
        default:
            return STG_E_INVALIDFUNCTION;
            break;
        }

        move = dlibMove.QuadPart;
        if((newPosition = lseek64(_fd, move, whence)) ==  (off64_t)-1)
            return STG_E_SEEKERROR;

        memset(plibNewPosition, 0, sizeof(ULARGE_INTEGER));
        plibNewPosition->QuadPart = newPosition;
        return S_OK;
    }

    virtual HRESULT SetSize(/*[in]*/ ULARGE_INTEGER libNewSize)
    {
        return E_NOTIMPL;
    }

    virtual HRESULT CopyTo(/*[in]*/ IStream *pstm, /*[in]*/ ULARGE_INTEGER cb, /*[out]*/ ULARGE_INTEGER *pcbRead, /*[out]*/ ULARGE_INTEGER *pcbWritten)
    {
        return E_NOTIMPL;
    }

    virtual HRESULT Commit(/*[in]*/ unsigned long grfCommitFlags)
    {
        return E_NOTIMPL;
    }

    virtual HRESULT Revert()
    {
        return E_NOTIMPL;
    }

    virtual HRESULT LockRegion(/*[in]*/ ULARGE_INTEGER libOffset, /*[in]*/ ULARGE_INTEGER cb, /*[in]*/ unsigned long dwLockType)
    {
        return E_NOTIMPL;
    }

    virtual HRESULT UnlockRegion(/*[in]*/ ULARGE_INTEGER libOffset, /*[in]*/ ULARGE_INTEGER cb, /*[in]*/  unsigned long dwLockType)
    {
        return E_NOTIMPL;
    }

    virtual HRESULT Stat(/*[out]*/ STATSTG *pstatstg, /*[in]*/ unsigned long grfStatFlag)
    {
        return E_NOTIMPL;
    }

    virtual HRESULT Clone(/*[out]*/ IStream **ppstm)
    {
        return E_NOTIMPL;
    }
};

#endif // AEKAVD_POSIXISTREAM_H
