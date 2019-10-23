package com.venustech.tacacs.client;

import com.venustech.tacacs.UserInterface;
import com.venustech.tacacs.protocol.ClientSession;
import com.venustech.tacacs.protocol.entity.AuthenReply;
import com.venustech.tacacs.protocol.entity.AuthorReply;
import com.venustech.tacacs.protocol.entity.base.Argument;
import com.venustech.tacacs.protocol.enums.TACACS_PLUS;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author zhangxin
 * 2018/8/28
 */
public class TacacsClient {


    private String host, key;
    private int port;
    private final int timeoutMillis;
    final boolean singleConnect;
    final boolean unencrypted;

    /**
     * 通过加锁方式获取TacacsMessageHandler,
     * 此处由于channelFuture.addListener执行是异步的,可能导致未执行operationComplete方法就已经返回
     */
    private ReentrantLock lock = new ReentrantLock();
    private Condition connected = lock.newCondition();

    private EventLoopGroup eventLoopGroup = null;

    private TacacsMessageHandler tacacsMessageHandler = null;

    private Logger logger = LoggerFactory.getLogger(TacacsClient.class);

    public TacacsClient(String host, String key, int timeoutMillis, boolean singleConnect, boolean unencrypted){

        this.timeoutMillis = timeoutMillis;
        this.key = key;
        this.host = host;
        this.singleConnect = singleConnect;
        this.unencrypted = unencrypted;

            try {

                URI uri = new URI("http://" + host);
                host = uri.getHost();
                port = uri.getPort();
                if(port == -1) {
                    logger.info("TACACS+: No port assigned for host, \""+host+"\".  " +
                            "Using default port 49 instead.");
                    port = TacacsMessageHandler.PORT_TACACS;
                }
            }
            catch (URISyntaxException e) {
                logger.info("TACACS+: Bad port assigned for host, \""+host+"\".  " +
                        "Using default port 49 instead.");
                port = TacacsMessageHandler.PORT_TACACS;
            }
    }

    public TacacsClient(String host, String key, int timeoutMillis, boolean singleConnect) {
        this(host, key, timeoutMillis, singleConnect, false);
    }

    public TacacsClient(String host, String key) {
        this(host, key, 5000, false);
    }

    /**
     * 启动TacacsClient服务
     * @throws Exception
     */
    private synchronized void connectTacacsServer() throws Exception{

        if(eventLoopGroup == null){
            Bootstrap bootstrap = new Bootstrap();
            eventLoopGroup = new NioEventLoopGroup();
            bootstrap.group(eventLoopGroup)
                    .channel(NioSocketChannel.class)
                    .handler(new TacacsInitializer(key.getBytes("UTF-8")));
            ChannelFuture channelFuture = bootstrap.connect(host, port);
            logger.info("connect tacacs+ server " + host + " : " + port + " success");
            channelFuture.addListener((final ChannelFuture future) -> {
                if (future.isSuccess()) {
                    TacacsMessageHandler handler = future.channel().pipeline().get(TacacsMessageHandler.class);
                    tacacsMessageHandler = handler;
                    signalAvailableHandler();
                }
            });
        }

    }

    /**
     * addListener 成功后返回 tacacsMessageHandler
     */
    private void signalAvailableHandler() {
        lock.lock();
        try {
            connected.signalAll();
        } finally {
            lock.unlock();
        }
    }
    /**
     * addListener 异步执行,此处需要加锁等待 tacacsMessageHandler
     */
    private boolean waitingForHadler() throws InterruptedException{
        lock.lock();
        try {
            return connected.await(6000, TimeUnit.MILLISECONDS);
        } finally {
            lock.unlock();
        }
    }

    public TacacsMessageHandler chooseHandler(){
        while (this.tacacsMessageHandler == null) {
            try {
               waitingForHadler();
            } catch (InterruptedException e) {
                //logger.error("Waiting for available node is interrupted! ", e);
                throw new RuntimeException("Can't connect any servers!", e);
            }
        }
        return this.tacacsMessageHandler;
    }


    public void shutdown(){
        if(eventLoopGroup != null){
            eventLoopGroup.shutdownGracefully();
        }
    }

    private static void authenInteractive(String[] args, TacacsClient tc) throws Exception {
        UserInterface ui = UserInterface.getConsoleInstance(); // The UI will store the entered username... We'll need it for authorization.
        ClientSession s = tc.newSessionInteractive(TACACS_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TACACS_PLUS.PRIV_LVL.USER.code(), ui);
        AuthenReply authen = s.authenticate_ASCII();
        boolean result = s.handlePacket(authen);

        if(result){
            System.out.println();System.out.println();System.out.println();
            System.out.println("authentication success , starting authorize single cmd...");
            System.out.println();System.out.println();System.out.println();
            authorize(ui.getUsername(), tc, ui);
        }
    }

    private static void authorize(String username, TacacsClient tacacsClient, UserInterface ui) throws Exception {
        ClientSession s = tacacsClient.newSessionInteractive(TACACS_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TACACS_PLUS.PRIV_LVL.USER.code(), ui);
        boolean flag = true;
        while (flag){
            String cmd = ui.getUserInput("input a cmd(press e to exit):", false, TACACS_PLUS.AUTHEN.STATUS.FOLLOW);
            if("e".equals(cmd)){
                flag = false;
            }else{

                String[] cmd_args = cmd.split("\\s+");
                Argument[] arguments = new Argument[cmd_args.length + 1];
                arguments[0] = new Argument("service", "shell", false);
                for (int i = 0; i < cmd_args.length; i++) {

                    if (i == 0) {
                        arguments[1] = new Argument("cmd", cmd_args[i], false);
                    } else {
                        arguments[i + 1] = new Argument("cmd-arg", cmd_args[i], false);
                    }
                }

                AuthorReply author = s.authorize(
                        username,
                        TACACS_PLUS.AUTHEN.METH.TACACSPLUS,
                        TACACS_PLUS.AUTHEN.TYPE.ASCII,
                        TACACS_PLUS.AUTHEN.SVC.LOGIN,
                        arguments);
                boolean result = s.handlePacket(author);
                System.out.println("TACACS+: AUTHOR success ? " + result);
            }
        }


    }


    public synchronized ClientSession newSessionInteractive(TACACS_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, UserInterface ui) throws Exception {

        connectTacacsServer();
        TacacsMessageHandler t = chooseHandler();
        ClientSession s = new ClientSession(svc, port, rem_addr, priv_lvl, t, ui, singleConnect, unencrypted);
        t.addSession(s);
        return s;
    }

    public synchronized ClientSession newSession(TACACS_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl) throws Exception {
        connectTacacsServer();
        TacacsMessageHandler t = chooseHandler();
        ClientSession s = new ClientSession(svc, port, rem_addr, priv_lvl, t, singleConnect, unencrypted);
        t.addSession(s);
        return s;
    }

    public static void main(String[] args) throws Exception {

//        String host = "172.16.129.8";
      String host = "172.16.98.25";
        String key = "venus2017";

        TacacsClient tc = new TacacsClient(host, key);
        authenInteractive(args, tc);

        tc.shutdown();


    }

}
