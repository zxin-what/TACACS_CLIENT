package com.venustech.tacacs.client;

import com.venustech.tacacs.protocol.Session;
import com.venustech.tacacs.protocol.entity.base.Packet;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;

import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/**
 * @author zhangxin
 * 2018/8/28
 */
public class TacacsMessageHandler extends SimpleChannelInboundHandler<Packet> {

    public static final int PORT_TACACS = 49;
    public static final boolean DEBUG = false;

    /**
     * 存放所有TacacsFuture,接受服务器返回报文时移除对应
     */
    private ConcurrentHashMap<String, TacacsFuture> pendingTacacs = new ConcurrentHashMap();

    private final List<Session> sessions;
    private final byte[] key;
    private volatile boolean runnable;

    private volatile Channel channel;
    private SocketAddress remotePeer;

    public Channel getChannel() {
        return channel;
    }

    public SocketAddress getRemotePeer() {
        return remotePeer;
    }

    protected TacacsMessageHandler(byte[] key){
        this.key = key;
        this.runnable = true;
        this.sessions = new ArrayList<>();
    }

    public boolean isShutdown()
    {
        return !runnable;
    }

    protected final void addSession(Session s)
    {
        synchronized(sessions) { sessions.add(s); }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        super.channelActive(ctx);
        this.remotePeer = this.channel.remoteAddress();
    }

    @Override
    public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
        super.channelRegistered(ctx);
        this.channel = ctx.channel();
    }

    /**
     * 读取Tacacs服务器响应数据包
     * @param channelHandlerContext
     * @param packet
     * @throws Exception
     */
    @Override
    protected void channelRead0(ChannelHandlerContext channelHandlerContext, Packet packet) throws Exception {
        //read packet and handle packet
        String sessionId = new String(packet.header.getSessionID(), "UTF-8");
        TacacsFuture tacacsFuture = pendingTacacs.get(sessionId);
        if(tacacsFuture != null){
            pendingTacacs.remove(sessionId);
            tacacsFuture.done(packet);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ctx.close();
    }

    public void close() {
        channel.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * 向Tacacs服务器发送数据包
     * @param packet
     * @return
     */
    public TacacsFuture sendTacacsPacket(Packet packet){

        TacacsFuture tacacsFuture = null;

        try {
            final CountDownLatch latch = new CountDownLatch(1);
            tacacsFuture = new TacacsFuture(packet);
            String sessionId = new String(packet.header.getSessionID(), "UTF-8");
            pendingTacacs.put(sessionId, tacacsFuture);
            channel.writeAndFlush(packet).addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture channelFuture) throws Exception {
                    latch.countDown();
                }
            });
            latch.await();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return tacacsFuture;

    }
}
