package com.venustech.tacacs.client;

import com.venustech.tacacs.protocol.entity.base.Packet;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangxin
 * 2018/8/29
 */
public class TacacsEncoder extends MessageToByteEncoder<Packet> {

    private static final Logger LOG = LoggerFactory.getLogger(TacacsEncoder.class);

    private Class<?> genericClass;

    private byte[] key;

    public TacacsEncoder(Class<?> genericClass, byte[] key) {
        this.genericClass = genericClass;
        this.key = key;
    }


    @Override
    protected void encode(ChannelHandlerContext channelHandlerContext, Packet in, ByteBuf out) throws Exception {
        if (genericClass.isInstance(in)) {

            byte[] data = in.getWriteByte(key);
            LOG.info("TacacsClient packet : " + in.toString());
            out.writeBytes(data);
        }
    }
}
