package com.venustech.tacacs.client;

import com.venustech.tacacs.protocol.entity.AuthenReply;
import com.venustech.tacacs.protocol.entity.AuthorReply;
import com.venustech.tacacs.protocol.entity.base.Header;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * @author zhangxin
 * 2018/8/29
 */
public class TacacsDecoder extends LengthFieldBasedFrameDecoder {

    private static final Logger LOG = LoggerFactory.getLogger(TacacsEncoder.class);

    private Class<?> genericClass;

    private byte[] key;


    public TacacsDecoder(int maxFrameLength, int lengthFieldOffset, int lengthFieldLength,
                         int lengthAdjustment, int initialBytesToStrip, byte[] key) {
        super(maxFrameLength, lengthFieldOffset, lengthFieldLength, lengthAdjustment, initialBytesToStrip);
        this.key = key;
    }

    @Override
    protected Object decode(ChannelHandlerContext ctx, ByteBuf in) throws Exception {

        byte[] headerBytes = new byte[12];
        in.readBytes(headerBytes);
        Header header = new Header(headerBytes);
        byte[] body = new byte[header.bodyLength];
        in.readBytes(body); // read the body before potentially throwing any exceptions below, so that the input stream is left clean
        if (header.version==null) { throw new IOException("Received unknown packet header version code: "+((headerBytes[0]&0xf0)>>>4)+"."+(headerBytes[0]&0x0f)); }
        if (header.type==null) { throw new IOException("Received unknown packet header type code: "+headerBytes[1]); }
        byte[] bodyClear;
        try { bodyClear = header.toggleCipher(body, key); } catch (NoSuchAlgorithmException e) { throw new IOException(e.getMessage()); }
        switch (header.type)
        {
            case AUTHEN:
                AuthenReply authenReply = new AuthenReply(header, bodyClear);
                LOG.info("TacacsServer AUTHEN packet : " + authenReply.toString());
                return authenReply;
            case AUTHOR:
                AuthorReply authorReply = new AuthorReply(header, bodyClear);
                LOG.info("TacacsServer AUTHOR packet : " + authorReply.toString());
                return authorReply;

            default: throw new IOException("Client-side packet header type not supported: " + header.type); // shouldn't happen
        }
    }
}
