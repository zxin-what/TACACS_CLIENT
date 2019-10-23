package com.venustech.tacacs.client;

import com.venustech.tacacs.protocol.entity.base.Packet;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;


/**
 * @author zhangxin
 * 2018/8/29
 */
public class TacacsInitializer extends ChannelInitializer<SocketChannel> {

    private byte[] key;

    public TacacsInitializer(byte[] key){
        this.key = key;
    }

    @Override
    protected void initChannel(SocketChannel socketChannel) throws Exception {
        ChannelPipeline cp = socketChannel.pipeline();
        cp.addLast(new TacacsEncoder(Packet.class, key));
        cp.addLast(new TacacsDecoder(65536, 0, 4, 0, 0, key));
        cp.addLast(new TacacsMessageHandler(key));
    }
}
