/*
 * zlib_wrapper.h - Wrapper for z.library API compatibility
 * 
 * This file provides compatibility between the standard zlib API
 * and the AmigaOS z.library API for AWebZen.
 */

#ifndef ZLIB_WRAPPER_H
#define ZLIB_WRAPPER_H

#include <exec/types.h>
#include <libraries/z.h>

/* Open z.library */
extern struct Library *ZLibBase;

/* Function prototypes that map zlib functions to z.library API */
#define zlibVersion() ZlibVersion()

/* Compression functions */
#define deflateInit(strm, level) DeflateInit(strm, level)
#define deflate(strm, flush) Deflate(strm, flush)
#define deflateEnd(strm) DeflateEnd(strm)
#define deflateInit2(strm, level, method, windowBits, memLevel, strategy) \
    DeflateInit2(strm, level, method, windowBits, memLevel, strategy)
#define deflateSetDictionary(strm, dictionary, dictLength) \
    DeflateSetDictionary(strm, dictionary, dictLength)
#define deflateCopy(dest, source) DeflateCopy(dest, source)
#define deflateReset(strm) DeflateReset(strm)
#define deflateParams(strm, level, strategy) DeflateParams(strm, level, strategy)
#define deflateBound(strm, sourceLen) DeflateBound(strm, sourceLen)
#define deflatePrime(strm, bits, value) DeflatePrime(strm, bits, value)
#define deflateSetHeader(strm, head) DeflateSetHeader(strm, head)
#define deflateTune(strm, good_length, max_lazy, nice_length, max_chain) \
    DeflateTune(strm, good_length, max_lazy, nice_length, max_chain)

/* Decompression functions */
#define inflateInit(strm) InflateInit(strm)
#define inflate(strm, flush) Inflate(strm, flush)
#define inflateEnd(strm) InflateEnd(strm)
#define inflateInit2(strm, windowBits) InflateInit2(strm, windowBits)
#define inflateSetDictionary(strm, dictionary, dictLength) \
    InflateSetDictionary(strm, dictionary, dictLength)
#define inflateReset(strm) InflateReset(strm)
#define inflateCopy(dest, source) InflateCopy(dest, source)
#define inflatePrime(strm, bits, value) InflatePrime(strm, bits, value)
#define inflateGetHeader(strm, head) InflateGetHeader(strm, head)
#define inflateBackInit(strm, windowBits, window) \
    InflateBackInit(strm, windowBits, window)
#define inflateBack(strm, in, in_desc, out, out_desc) \
    InflateBack(strm, in, in_desc, out, out_desc)
#define inflateBackEnd(strm) InflateBackEnd(strm)
#define inflateSync(strm) InflateSync(strm)
#define inflateReset2(strm, windowBits) InflateReset2(strm, windowBits)
#define inflateValidate(strm, check) InflateValidate(strm, check)
#define inflateGetDictionary(strm, dictionary, dictLength) \
    InflateGetDictionary(strm, dictionary, dictLength)

/* Utility functions */
#define compress(dest, destLen, source, sourceLen) \
    Compress(dest, destLen, source, sourceLen)
#define uncompress(dest, destLen, source, sourceLen) \
    Uncompress(dest, destLen, source, sourceLen)
#define compress2(dest, destLen, source, sourceLen, level) \
    Compress2(dest, destLen, source, sourceLen, level)
#define uncompress2(dest, destLen, source, sourceLen) \
    Uncompress2(dest, destLen, source, sourceLen)
#define compressBound(sourceLen) CompressBound(sourceLen)

/* Checksum functions */
#define adler32(adler, buf, len) Adler32(adler, buf, len)
#define crc32(crc, buf, len) CRC32(crc, buf, len)
#define adler32Combine(adler1, adler2, len2) \
    Adler32Combine(adler1, adler2, len2)
#define crc32Combine(crc1, crc2, len2) CRC32Combine(crc1, crc2, len2)
#define crc32CombineGen(len2) CRC32CombineGen(len2)
#define crc32CombineOp(crc1, crc2, op) CRC32CombineOp(crc1, crc2, op)

/* Error handling */
#define zError(err) ZError(err)

/* Library initialization function */
LONG InitZLib(void);
void CleanupZLib(void);

#endif /* ZLIB_WRAPPER_H */ 