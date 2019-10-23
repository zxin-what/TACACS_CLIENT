package com.venustech.tacacs.protocol.entity.base;

import com.venustech.tacacs.protocol.enums.TACACS_PLUS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author zhangxin
 * 2018/8/27
 */
public class Header {

    static final int FF = 0xFF;
    /** 会话中唯一的序列号 **/
    final byte seqNum;
    /** 此字段包含各种位映射标志 **/
    final byte flags;
    /** 版本 **/
    public final TACACS_PLUS.PACKET.VERSION version;
    /** 报文类型 **/
    public final TACACS_PLUS.PACKET.TYPE type;
    /** 此次TACACS+会话ID **/
    final byte[] sessionID;
    /** 客户端解码服务端响应的数据包时设置;程序创建时不需设置,在writePacket调用时根据需要计算主体的长度 **/
    public final int bodyLength;


    private Header(byte seqNum, byte flags, TACACS_PLUS.PACKET.VERSION version, TACACS_PLUS.PACKET.TYPE type, byte[] sessionID) {
        this.seqNum = seqNum;
        this.flags = flags;
        this.version = version;
        this.type = type;
        this.sessionID = sessionID;
        this.bodyLength = -1;
    }

    public Header(byte flags, TACACS_PLUS.PACKET.VERSION version, TACACS_PLUS.PACKET.TYPE type, byte[] sessionID) {
        this(
                (byte)1,
                flags,
                version,
                type,
                sessionID
        );
    }

    /** 接收数据包时在内部使用 **/
    public Header(byte[] bytes)
    {
        version = TACACS_PLUS.PACKET.VERSION.forCode(bytes[0]);
        type = TACACS_PLUS.PACKET.TYPE.forCode(bytes[1]);
        seqNum = bytes[2];
        flags = bytes[3];
        sessionID = Arrays.copyOfRange(bytes, 4, 8);
        bodyLength = toInt(bytes[8],bytes[9],bytes[10],bytes[11]);
    }
    static int toInt(byte a, byte b, byte c, byte d)
    {
        return ((a&FF)<<24) | (b&FF<<16) | ((c&FF)<<8) | (d&FF);
    }

    /**
     * 为SessionClient创建响应报文,支持单连接模式
     * @param version
     * @return
     * @throws IOException
     */
    public Header next(TACACS_PLUS.PACKET.VERSION version) throws IOException
    {
        if ((FF&seqNum)>=FF) { throw new IOException("Session's sequence numbers exhausted; try new session."); }
        return new Header((byte)((Packet.FF&seqNum)+1), flags, version, type, sessionID);
    }

    public boolean hasFlag(TACACS_PLUS.PACKET.FLAG flag)
    {
        return (flags & flag.code()) != 0;
    }

    public byte[] getSessionID(){
        return sessionID;
    }

    /**
     * Toggles the encryption of the given packet body byte[] returning the result.
     * The calculation depends on the given key, and these header fields:
     * sessionID, version, and seqNum.
     * @param body
     * @param key
     * @throws NoSuchAlgorithmException if the MD5 message digest can't be found; shouldn't happen.
     * @return A new byte[] containing the ciphered/deciphered body; or just
     * the unchanged body itself if TAC_PLUS.PACKET.FLAG.UNENCRYPTED is set.
     */
    public byte[] toggleCipher(byte[] body, byte[] key) throws NoSuchAlgorithmException {
        if (hasFlag(TACACS_PLUS.PACKET.FLAG.UNENCRYPTED)) { return body; }
        MessageDigest md = MessageDigest.getInstance("MD5");
        int length = body.length;
        byte[] pad = new byte[length];
        md.update(sessionID); // reset() not necessary since each digest() resets
        md.update(key);
        md.update(version.code());
        md.update(seqNum);
        byte[] digest=md.digest(); // first digest applies only header info
        System.arraycopy(digest, 0, pad, 0, Math.min(digest.length,length));
        length -= digest.length;
        int pos = digest.length;
        while (length>0)
        {
            md.update(sessionID);
            md.update(key);
            md.update(version.code());
            md.update(seqNum);
            md.update(Arrays.copyOfRange(pad, pos-digest.length, pos)); // apply previous digest too
            digest=md.digest();
            System.arraycopy(digest, 0, pad, pos, Math.min(digest.length,length));
            pos += digest.length;
            length -= digest.length;
        }
        byte[] toggled = new byte[body.length];
        for (int i=body.length-1; i>=0; i--)
        {
            toggled[i] = (byte)((body[i] & 0xff) ^ (pad[i] & 0xff));
        }
        return toggled;
    }

    public byte[] writePacket(byte[] body, byte[] key) throws IOException {
        int len = body.length;
        ByteArrayOutputStream bout = new ByteArrayOutputStream(12+len);
        bout.write(version.code());
        bout.write(type.code());
        bout.write(seqNum);
        bout.write(flags);
        bout.write(sessionID);
        bout.write(Packet.toBytes4(len));
        try { bout.write(toggleCipher(body, key)); } catch (NoSuchAlgorithmException e) { throw new IOException(e.getMessage()); }
        return bout.toByteArray();
    }
}
