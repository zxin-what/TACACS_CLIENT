package com.venustech.tacacs.protocol.entity;

import com.venustech.tacacs.protocol.entity.base.Header;
import com.venustech.tacacs.protocol.entity.base.Packet;
import com.venustech.tacacs.protocol.enums.TACACS_PLUS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author zhangxin
 * 2018/8/28
 */
public class AuthenReply extends Packet{

    public final TACACS_PLUS.AUTHEN.STATUS status;
    final byte flags;
    public final String server_msg;
    final String data;


    AuthenReply(Header header, TACACS_PLUS.AUTHEN.STATUS status, byte flags, String server_msg, String data){

        super(header);
        this.status = status;
        this.flags = flags;
        this.server_msg = server_msg;
        this.data = data;
    }

    public AuthenReply(Header header, byte[] body) throws IOException
    {
        super(header);
        // Verify...
        int overhead = 6;
        if (body.length<overhead) { throw new IOException("Corrupt packet or bad key"); }
        int msgLen = toInt(body[2],body[3]);
        int dataLen = toInt(body[4],body[5]);
        int chkLen = overhead + msgLen + dataLen;
        if (chkLen != body.length) { throw new IOException("Corrupt packet or bad key"); }
        //
        status = TACACS_PLUS.AUTHEN.STATUS.forCode(body[0]);
        if (status == null) { throw new IOException("Received unknown TAC_PLUS_AUTHEN_STATUS code: "+body[0]); }
        flags = body[1];
        server_msg = (msgLen>0) ? new String(body, 6, msgLen, StandardCharsets.UTF_8) : null;
        data = (dataLen>0) ? new String(body, 6+msgLen, dataLen, StandardCharsets.UTF_8) : null;
    }

    public boolean isOK() {
        return status == TACACS_PLUS.AUTHEN.STATUS.PASS;
    }

    public boolean hasFlag(TACACS_PLUS.REPLY.FLAG flag)
    {
        return (flags & flag.code()) != 0;
    }

    public String getServerMsg()
    {
        return server_msg;
    }


    public String getData()
    {
        return data;
    }

    @Override
    public byte[] getWriteByte(byte[] key) throws IOException {
        byte[] smsgBytes = server_msg==null?null:server_msg.getBytes(StandardCharsets.UTF_8);
        byte[] dataBytes = data==null?null:data.getBytes(StandardCharsets.UTF_8);
        // Truncating to fit packet...  lengths are limited to a 16 bits
        if (smsgBytes!=null && smsgBytes.length>FFFF) { smsgBytes = Arrays.copyOfRange(smsgBytes,0,FFFF); }
        if (dataBytes!=null && dataBytes.length>FFFF) { dataBytes = Arrays.copyOfRange(dataBytes,0,FFFF); }
        ByteArrayOutputStream body = new ByteArrayOutputStream(6 + (smsgBytes==null?0:smsgBytes.length) + (dataBytes==null?0:dataBytes.length));
        body.write(status.code());
        body.write(flags);
        body.write(toBytes2(smsgBytes==null?0:smsgBytes.length));
        body.write(toBytes2(dataBytes==null?0:dataBytes.length));
        if (smsgBytes!=null) { body.write(smsgBytes); }
        if (dataBytes!=null) { body.write(dataBytes); }
        byte[] bodyBytes = body.toByteArray();
        header.writePacket(bodyBytes, key);
        return header.writePacket(bodyBytes, key);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()+":"+header+"[status:"+status+" flags:"+flags+" server_msg:'"+server_msg+"' data:'"+data+"']";
    }
}
