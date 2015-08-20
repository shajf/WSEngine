
/**
 * @file ngx_base64.h
 * @brief NGX-UTIL Base64 Encoding
 */
#ifndef NGX_BASE64_H
#define NGX_BASE64_H

#include <ngx_config.h>
#include <ngx_core.h>

/* Simple BASE64 encode/decode functions.
 * 
 * As we might encode binary strings, hence we require the length of
 * the incoming plain source. And return the length of what we decoded.
 *
 * The decoding function takes any non valid char (i.e. whitespace, \0
 * or anything non A-Z,0-9 etc as terminal.
 * 
 * plain strings/binary sequences are not assumed '\0' terminated. Encoded
 * strings are neither. But probably should.
 *
 */

/**
 * Given the length of an un-encrypted string, get the length of the 
 * encrypted string.
 * @param len the length of an unencrypted string.
 * @return the length of the string after it is encrypted
 */ 
int ngx_base64_encode_len(int len);

/**
 * Encode a text string using base64encoding.
 * @param coded_dst The destination string for the encoded string.
 * @param plain_src The original string in plain text
 * @param len_plain_src The length of the plain text string
 * @return the length of the encoded string
 */ 
int ngx_base64_encode(char * coded_dst, const char *plain_src, 
                                 int len_plain_src);

/**
 * Encode an EBCDIC string using base64encoding.
 * @param coded_dst The destination string for the encoded string.
 * @param plain_src The original string in plain text
 * @param len_plain_src The length of the plain text string
 * @return the length of the encoded string
 */ 
int ngx_base64_encode_binary(char * coded_dst, 
                                        const unsigned char *plain_src,
                                        int len_plain_src);

/**
 * Determine the maximum buffer length required to decode the plain text
 * string given the encoded string.
 * @param coded_src The encoded string
 * @return the maximum required buffer length for the plain text string
 */ 
int ngx_base64_decode_len(const char * coded_src);

/**
 * Decode a string to plain text
 * @param plain_dst The destination string for the plain text
 * @param coded_src The encoded string 
 * @return the length of the plain text string
 */ 
int ngx_base64_decode(char * plain_dst, const char *coded_src);

/**
 * Decode an EBCDIC string to plain text
 * @param plain_dst The destination string for the plain text
 * @param coded_src The encoded string 
 * @return the length of the plain text string
 */ 
int ngx_base64_decode_binary(unsigned char * plain_dst, 
                                        const char *coded_src);

#endif	/* !NGX_BASE64_H */
